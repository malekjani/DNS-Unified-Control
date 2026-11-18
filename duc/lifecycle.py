"""DNS Unified Control v0.10.6 lifecycle: one safe entry for fresh, resume, upgrade, repair.

No Cloudflare mutations, DNS engine switching, credential exports or TOTP reset.
The journal contains only operation metadata, never tokens or passwords.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import http.client
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
from typing import Callable

from . import instance, fresh_setup, web_install
from .confirm import ask_yes_no

SCHEMA = 'duc.lifecycle.v1'
BASE = Path('/var/lib/dns-unified/lifecycle')
BACKUPS = Path('/var/backups/dns-unified')
LOCK = Path('/run/lock/duc-lifecycle.lock')
APP = Path('/opt/dns-unified-control')
AGENT_SOCKET = Path('/run/dns-unified-agent.sock')
UNIT_NAMES = ('dns-unified-web.service', 'dns-unified-agent.service',
               'dns-unified-agent.socket', 'dns-unified@.service',
              'dns-unified-multi@.service', 'dns-unified-multi-router.service')
STAGES_FRESH = ('instance', 'swap', 'runtime', 'dante', 'profiles', 'engines', 'health', 'tls_status')
STAGES_UPGRADE = ('snapshot', 'apply', 'health', 'tls_status')
STAGES_REPAIR = ('permissions', 'health', 'tls_status')


class LifecycleError(RuntimeError):
    pass


def utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def version_tuple(v: str) -> tuple[int, ...]:
    try:
        parts = tuple(int(s) for s in v.strip().split('.'))
        if not 2 <= len(parts) <= 4:
            raise ValueError
        return parts
    except ValueError as exc:
        raise LifecycleError(f'Unrecognized release version: {v!r}') from exc


def read_version(path: Path) -> str | None:
    if not path.is_file():
        return None
    return path.read_text(encoding='utf-8').strip()


def decide(target: str, installed: str | None, identity: dict | None,
           journal: dict | None, *, app_exists: bool) -> str:
    """Side-effect-free operation decision. Downgrades fail closed."""
    target_v = version_tuple(target)
    if installed is not None and version_tuple(installed) > target_v:
        raise LifecycleError('Installed version is newer than this package; downgrade refused')
    if journal and journal.get('schema') != SCHEMA:
        raise LifecycleError('Unknown lifecycle journal schema; refusing automatic repair')
    if journal and journal.get('status') in ('running', 'failed', 'failed_rolled_back'):
        if journal.get('release') == target and journal.get('operation') in ('fresh', 'upgrade', 'repair'):
            if identity and journal.get('instance_id') not in (None, identity['instance_id']):
                raise LifecycleError('Lifecycle journal belongs to a different instance')
            return 'resume'
        # A newer release may upgrade an older incomplete install, but only if
        # the installed runtime really exists; otherwise keep the old recovery path.
        if not (identity and app_exists and installed and version_tuple(installed) < target_v):
            raise LifecycleError('Unfinished operation for another release; inspect --status before proceeding')
    if identity is None:
        if app_exists or installed:
            return 'legacy_upgrade'
        return 'fresh'
    if not app_exists or not installed:
        return 'resume_fresh'
    if version_tuple(installed) < target_v:
        return 'upgrade'
    return 'repair'


def _safe_path(path: Path) -> None:
    if path.is_symlink():
        raise LifecycleError(f'Refusing symlinked lifecycle path: {path}')


def load_state(path: Path = BASE / 'state.json') -> dict | None:
    _safe_path(path)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise LifecycleError('Lifecycle state is corrupt; refusing automatic overwrite') from exc
    if not isinstance(data, dict) or data.get('schema') != SCHEMA:
        raise LifecycleError('Unknown lifecycle state schema')
    return data


def write_state(state: dict, path: Path = BASE / 'state.json') -> None:
    """Durable, restrictive root-only atomic journal; no secrets in values."""
    parent = path.parent
    _safe_path(parent)
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _safe_path(path)
    os.chmod(parent, 0o700)
    fd, tmp_name = tempfile.mkstemp(prefix='.lifecycle-', dir=parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as writer:
            json.dump(state, writer, ensure_ascii=False, indent=2, sort_keys=True)
            writer.write('\n')
            writer.flush()
            os.fsync(writer.fileno())
        os.replace(tmp_name, path)
        dir_fd = os.open(parent, os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


@contextmanager
def exclusive_lock(path: Path = LOCK):
    _safe_path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('a+b') as handle:
        os.chmod(path, 0o600)
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise LifecycleError('Another DUC lifecycle operation is already running') from exc
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def new_state(operation: str, release: str, identity: dict | None, options: dict) -> dict:
    return {'schema': SCHEMA, 'operation': operation, 'release': release,
            'instance_id': identity['instance_id'] if identity else None,
            'domain': options.get('domain') or (identity or {}).get('domain'),
            'public_ipv4': options.get('ip') or (identity or {}).get('public_ipv4'),
            'with_engines': bool(options.get('with_engines', False)),
            'create_swap': bool(options.get('swap', False)),
            'status': 'running', 'started_utc': utc(), 'updated_utc': utc(),
            'steps': {}, 'backup': None, 'error': None}


def mark(state: dict, step: str, status: str, *, note: str | None = None,
         store: Callable[[dict], None] = write_state) -> None:
    if status not in ('started', 'completed', 'failed', 'skipped'):
        raise ValueError('invalid lifecycle stage status')
    state['steps'][step] = {'status': status, 'time': utc()}
    if note:
        state['steps'][step]['note'] = note[:200]
    state['updated_utc'] = utc()
    store(state)


def command(argv: list[str], *, env: dict | None = None) -> None:
    # Deliberately no shell=True and no credentials in argv.
    subprocess.run(argv, check=True, env=env)


def call_env(**values: str) -> dict:
    return {**os.environ, **values}


def check_agent(socket_path: Path = AGENT_SOCKET) -> bool:
    """Exercise actual privileged API rather than trusting active socket alone."""
    class UnixHTTP(http.client.HTTPConnection):
        def connect(self):
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.settimeout(5)
            self.sock.connect(str(socket_path))
    try:
        conn = UnixHTTP('localhost', timeout=5)
        try:
            conn.request('GET', '/status')
            res = conn.getresponse()
            body = res.read(2_000_000)
            if res.status != 200:
                return False
            data = json.loads(body)
            return isinstance(data.get('active'), list) and isinstance(data.get('engines'), dict)
        finally:
            conn.close()
    except (OSError, ValueError, KeyError, http.client.HTTPException):
        return False


def health(*, require_dante: bool = True) -> None:
    command(['bash', 'scripts/check-local-health.sh'])
    if not check_agent():
        raise LifecycleError('Agent socket is active but GET /status did not return a valid response')
    if require_dante:
        result = subprocess.run([str(APP / '.venv/bin/python'), '-m', 'duc.dante', 'status'],
                                capture_output=True, text=True,
                                env=call_env(PYTHONPATH=str(APP)), check=False, timeout=15)
        try:
            status = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise LifecycleError('Dante status is not valid JSON') from exc
        if result.returncode or not status.get('ready') or status.get('bind') != '127.0.0.1:1080':
            raise LifecycleError('Dante backend is not authenticated/ready on localhost:1080')
    print('HEALTH: Web HTTP ready, Agent GET /status verified' + (', Dante ready' if require_dante else ''))


def maintenance_preflight() -> None:
    """Do not flag the already-running DUC ports as new install conflicts."""
    r = fresh_setup.collect(resume=True)
    relevant = {'os', 'systemd', 'apt', 'disk', 'memory'}
    bad = [x for x in r['checks'] if x['id'] in relevant and x['status'] == 'block']
    for item in r['checks']:
        if item['id'] in relevant:
            print(f"[{item['status'].upper()}] {item['id']}: {item['message']}")
    if bad:
        raise LifecycleError('Maintenance preflight failed: ' + ', '.join(x['id'] for x in bad))


def safe_archive_name(backup_dir: Path, identity: dict | None) -> Path:
    backup_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(backup_dir, 0o700)
    instance_part = (identity or {}).get('instance_id', 'legacy')[:8]
    return backup_dir / ('pre-upgrade-' + instance_part + '-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ') + '.tar.gz')


def snapshot_code(backup_dir: Path = BACKUPS, app_root: Path = APP,
                  units_root: Path = Path('/etc/systemd/system'), identity: dict | None = None) -> Path:
    """Code+unit snapshot only. Keys/MFA/Dante are NEVER restored over live state."""
    if not app_root.is_dir():
        raise LifecycleError('Installed application tree missing; cannot snapshot upgrade')
    _safe_path(backup_dir)
    name = safe_archive_name(backup_dir, identity)
    try:
        with tarfile.open(name, 'w:gz') as tar:
            tar.add(app_root, arcname='app', recursive=True)
            for item in UNIT_NAMES:
                unit = units_root / item
                if unit.is_file() and not unit.is_symlink():
                    tar.add(unit, arcname='units/' + item)
        os.chmod(name, 0o600)
        if name.stat().st_size == 0:
            raise LifecycleError('Empty snapshot')
    except BaseException:
        name.unlink(missing_ok=True)
        raise
    print(f'CODE SNAPSHOT (root-only): {name}')
    return name


def rollback_code(snapshot: Path, app_root: Path = APP,
                  units_root: Path = Path('/etc/systemd/system'),
                  *, restart: bool = True) -> None:
    """Best-effort rollback of application tree and systemd units, not system packages.

    Not a general-purpose machine transaction. No Cloudflare, profile, engine,
    secret or OS dependency rollback is claimed.
    """
    _safe_path(snapshot)
    if not snapshot.is_file():
        raise LifecycleError('Snapshot unavailable; manual recovery is required')
    with tempfile.TemporaryDirectory(prefix='duc-rollback-') as work:
        staging = Path(work)
        with tarfile.open(snapshot, 'r:gz') as tar:
            members = tar.getmembers()
            for member in members:
                if not (member.name == 'app' or member.name.startswith('app/') or
                        member.name.startswith('units/')):
                    raise LifecycleError('Unsafe snapshot contents')
                if '..' in Path(member.name).parts or Path(member.name).is_absolute() or member.isdev() or member.islnk():
                    raise LifecycleError('Unsafe snapshot member path or type')
                if member.issym():
                    # Python venvs use links to the system interpreter; allow
                    # only well-known interpreter links or contained links.
                    if not member.name.startswith('app/'):
                        raise LifecycleError('Unexpected symlink outside application')
                    target = Path(member.linkname)
                    if target.is_absolute():
                        if not (member.name.startswith('app/.venv/') and
                                str(target) in ('/usr/bin/python3', '/usr/bin/python3.12',
                                                '/usr/local/bin/python3', '/usr/local/bin/python3.12')):
                            raise LifecycleError('Unexpected external symlink')
                    else:
                        resolved = ((staging / member.name).parent / target).resolve()
                        if not resolved.is_relative_to((staging / 'app').resolve()):
                            raise LifecycleError('Symlink points outside application')
            # Source archive created locally and root-only. Validate members
            # above before allowing the approved interpreter symlinks.
            tar.extractall(staging, filter='fully_trusted')
        source = staging / 'app'
        if not source.is_dir():
            raise LifecycleError('Invalid code snapshot: no application directory')
        failed_tree = app_root.with_name(app_root.name + '.failed-upgrade-' +
                                         datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
        if app_root.exists():
            app_root.rename(failed_tree)
        try:
            shutil.move(str(source), str(app_root))
        except BaseException:
            if failed_tree.exists() and not app_root.exists():
                failed_tree.rename(app_root)
            raise
        # Keep failed tree for root inspection; it contains code (not secrets).
        for unit in UNIT_NAMES:
            source_unit = staging / 'units' / unit
            if source_unit.is_file():
                shutil.copy2(source_unit, units_root / unit)
            elif unit in ('dns-unified-multi@.service', 'dns-unified-multi-router.service'):
                # If upgrading from a pre-Multi release failed, remove newly
                # introduced, uncommitted unit templates. Existing custom
                # units were included in the snapshot and are restored above.
                current_unit = units_root / unit
                if current_unit.is_file() and not current_unit.is_symlink():
                    current_unit.unlink()
    if restart:
        command(['systemctl', 'daemon-reload'])
        command(['systemctl', 'reset-failed', 'dns-unified-web.service'])
        command(['systemctl', 'restart', 'dns-unified-web.service'])
        command(['systemctl', 'try-restart', 'dns-unified-agent.service'])
    print('Code and service units restored from snapshot; system packages and secrets untouched.')


def _prompt(label: str, default: str = '') -> str:
    suffix = f' [{default}]' if default else ''
    result = input(f'{label}{suffix}: ').strip()
    return result or default


def _yes(label: str) -> bool:
    return ask_yes_no(label)


def wizard_fresh() -> dict:
    report = fresh_setup.collect()
    for check in report['checks']:
        print(f"[{check['status'].upper()}] {check['id']}: {check['message']}")
    if not report['ready_for_base_install']:
        raise LifecycleError('Blocking preflight issue: no changes applied')
    while True:
        try:
            domain = fresh_setup.valid_domain(_prompt('Base domain (e.g. example.com)'))
            break
        except ValueError as exc:
            print(exc, file=sys.stderr)
    while True:
        try:
            public_ip = fresh_setup.valid_public_ip(_prompt('Public IPv4 from provider (not private NIC IP)'))
            break
        except ValueError as exc:
            print(exc, file=sys.stderr)
    # Important for EC2: private ens5 IP is expected; instance uses public NAT IP.
    print('Cloudflare DNS records will NOT be modified or migrated.')
    if _yes('Verify Cloudflare Zone Read token once (not saved)?'):
        from .guided_setup import verify_cloudflare
        verified = verify_cloudflare(domain)
        if not verified:
            print('Read-only token check failed or skipped; no DNS changes.')
    swap = False
    mem = fresh_setup.parse_meminfo(Path('/proc/meminfo').read_text())
    if mem.get('SwapTotal', 0) == 0 and mem.get('MemTotal', 0) < 1536 * 1024 * 1024:
        swap = _yes('Create 2 GiB swap before optional builds?')
    engines = _yes('Install additional supported engines after base installation?')
    print('HTTPS certificate and public routing are required to finish Web setup; they are part of the install lifecycle.')
    return {'domain': domain, 'ip': public_ip, 'swap': swap, 'with_engines': engines}


def repair_web() -> None:
    command(['bash', 'scripts/ensure-runtime-access.sh'])
    command(['systemctl', 'reset-failed', 'dns-unified-web.service'])
    command(['systemctl', 'restart', 'dns-unified-web.service'])


def _run_stage(state: dict, name: str, action: Callable[[], None], *,
               validator: Callable[[], bool] | None = None,
               store: Callable[[dict], None] = write_state) -> None:
    previous = state['steps'].get(name, {}).get('status')
    if previous == 'completed' and (validator is None or validator()):
        print(f'CHECKPOINT {name}: completed; skipping')
        return
    mark(state, name, 'started', store=store)
    try:
        action()
    except BaseException as exc:
        mark(state, name, 'failed', note=type(exc).__name__, store=store)
        raise
    mark(state, name, 'completed', store=store)
    print(f'CHECKPOINT {name}: completed')


def _cmd(argv: list[str], env: dict | None = None) -> None:
    command(argv, env=env)


def tls_readiness(state: dict, store: Callable[[dict], None] = write_state) -> None:
    result = subprocess.run(['bash', 'scripts/panel-https-status.sh'],
                            check=True, capture_output=True, text=True, timeout=18)
    print(result.stdout.strip())
    tls = next((line.split('=', 1)[1].split()[0] for line in result.stdout.splitlines()
                if line.startswith('PANEL_HTTPS=')), 'UNKNOWN')
    dns = next((line.split('=', 1)[1].split()[0] for line in result.stdout.splitlines()
                if line.startswith('PANEL_DNS=')), 'UNKNOWN')
    if tls not in ('VERIFIED', 'DEFERRED', 'PENDING', 'UNCONFIGURED'):
        raise LifecycleError('HTTPS readiness was not reported by panel checker')
    state['tls'] = {'status': tls, 'dns': dns}
    state['certificate'] = web_install.certificate_status(
        'panel.' + state['domain'])
    store(state)


def execute(state: dict, *, identity: dict | None, installed: str | None,
            store: Callable[[dict], None] = write_state, offer_web: bool = False) -> None:
    op, opts = state['operation'], state
    is_upgrade = op in ('upgrade', 'legacy_upgrade')
    _run_stage(state, 'preflight', maintenance_preflight if op != 'fresh' or
               state.get('instance_id') else lambda: _fresh_gate(opts), store=store)
    if op == 'fresh':
        def identity_action():
            # Crash may occur after exclusive instance creation but before
            # journal commit. Reconcile the durable identity, never replace it.
            exists = instance.identity_path().exists()
            created = instance.initialize(opts['domain'], opts['public_ipv4'], resume=exists)
            state['instance_id'] = created['instance_id']
            store(state)
        _run_stage(state, 'instance', identity_action, validator=lambda: _identity_matches(state), store=store)
        if opts['create_swap']:
            _run_stage(state, 'swap', lambda: _cmd(['bash', 'scripts/ensure-swap.sh', '--create']), store=store)
        else:
            mark(state, 'swap', 'skipped', store=store)
        _run_stage(state, 'runtime', lambda: _cmd(['bash', './install.sh'],
                   env=call_env(DUC_INTERNAL_INSTALL='1', DUC_SKIP_WIZARD='1', DUC_INSTALL_ENGINES='0')),
                   validator=lambda: (APP / '.venv/bin/uvicorn').exists() and _web_unit_exists(), store=store)
        _run_stage(state, 'permissions', repair_web, validator=_web_agent_ready, store=store)
        _run_stage(state, 'dante', lambda: _cmd([str(APP / '.venv/bin/python'), '-m', 'duc.dante', 'install'],
                   env=call_env(PYTHONPATH=str(APP))), validator=_dante_status_quick, store=store)
        _run_stage(state, 'profiles', lambda: _cmd([str(APP / '.venv/bin/python'), '-m',
                   'duc.fresh_setup', 'profiles', '--domain', opts['domain']], env=call_env(PYTHONPATH=str(APP))),
                   validator=lambda: _profiles_match(opts['domain']), store=store)
        if opts['with_engines']:
            _run_stage(state, 'engines', lambda: _cmd(['bash', 'scripts/install-all-engines.sh']), store=store)
        else:
            mark(state, 'engines', 'skipped', store=store)
    elif is_upgrade:
        def take_snapshot():
            backup = snapshot_code(identity=identity)
            state['backup'] = str(backup)
            store(state)
        _run_stage(state, 'snapshot', take_snapshot,
                   validator=lambda: bool(state.get('backup') and Path(state['backup']).is_file()), store=store)
        _run_stage(state, 'apply', lambda: _cmd(['bash', './install.sh'], env=call_env(
                   DUC_INTERNAL_INSTALL='1', DUC_SKIP_WIZARD='1', DUC_INSTALL_ENGINES='0',
                   DUC_LIFECYCLE_SKIP_PROVISION='1')),
                   validator=lambda: read_version(APP / 'VERSION') == state['release'], store=store)
        _run_stage(state, 'permissions', repair_web, validator=_web_agent_ready, store=store)
    else:  # idempotent repair: fix runtime permissions only, don't rebuild engine identities.
        _run_stage(state, 'permissions', repair_web, validator=_web_agent_ready, store=store)
    _run_stage(state, 'health', health, validator=lambda: _quick_health(), store=store)
    if offer_web:
        # Public HTTPS is part of the installation lifecycle, not an optional
        # *completion criterion*. A user may defer it to keep a working TUI.
        # Failure leaves Web INCOMPLETE and never rolls back healthy TUI code.
        onboard_web_certificate(state, store=store)
    _run_stage(state, 'tls_status', lambda: tls_readiness(state, store), store=store)
    component_status = web_install.web_components(state.get('tls') or {},
                                                   state.get('certificate') or {})
    state['components'] = component_status
    complete = component_status['web']['status'] == 'READY'
    state['outcome'] = 'READY' if complete else 'TUI_READY_WEB_INCOMPLETE'
    state['status'] = 'completed' if complete else 'partial'
    state['error'] = None
    state['updated_utc'] = utc()
    store(state)
    print(f"LIFECYCLE: {state['outcome']} (TUI/local Agent and Dante verified).")
    if not complete:
        print('WEB INSTALL INCOMPLETE: valid certificate, renewal, HTTPS route and panel DNS must pass. ' \
              'DNS tunnel NS cutover remains a separate guarded action.')


def onboard_web_certificate(state: dict, *, store: Callable[[dict], None] = write_state) -> None:
    fqdn = 'panel.' + state['domain']
    current = web_install.certificate_status(fqdn)
    if current['certificate'] == 'VALID' and current['renewal'] == 'CONFIGURED':
        mark(state, 'web_certificate', 'completed', store=store)
        print('WEB CERTIFICATE: valid and renewal credentials configured')
        return
    print(f"WEB CERTIFICATE: {current['certificate']}; RENEWAL: {current['renewal']}")
    print('A valid, renewable HTTPS certificate is REQUIRED for completed Web installation.')
    print('A working local TUI remains usable if Web setup is deferred.')
    if not ask_yes_no('Configure/repair Web TLS via Cloudflare DNS-01 now?'):
        mark(state, 'web_certificate', 'skipped', store=store)
        return
    mark(state, 'web_certificate', 'started', store=store)
    try:
        command(['bash', 'scripts/cert-cloudflare-dns01.sh', fqdn])
    except (subprocess.CalledProcessError, OSError):
        mark(state, 'web_certificate', 'failed', store=store)
        print('WEB CERTIFICATE SETUP FAILED. TUI remains installed; Web is incomplete.')
        return
    result = web_install.certificate_status(fqdn)
    mark(state, 'web_certificate', 'completed' if result == {
        'certificate': 'VALID', 'renewal': 'CONFIGURED'} else 'failed', store=store)
    if result['renewal'] != 'CONFIGURED':
        print('WARNING: Certificate issued, but automatic renewal is not configured. Web remains INCOMPLETE.')


def _web_unit_exists() -> bool:
    return Path('/etc/systemd/system/dns-unified-web.service').is_file()


def _identity_matches(state: dict) -> bool:
    try:
        identity = instance.load()
        return (identity['domain'] == state['domain'] and
                identity['public_ipv4'] == state['public_ipv4'] and
                identity['instance_id'] == state['instance_id'])
    except (instance.InstanceError, OSError):
        return False


def _profiles_match(domain: str) -> bool:
    try:
        import importlib
        core = importlib.import_module('duc.core')
        catalog = importlib.import_module('duc.catalog')
        return all(core.profiles()[key]['domain'] == f'{catalog.LABELS[key]}.{domain}' for key in catalog.ENGINES)
    except Exception:
        return False


def _dante_status_quick() -> bool:
    return Path('/etc/dns-unified/keys/dante-auth.json').is_file()


def _web_agent_ready() -> bool:
    try:
        subprocess.run(['bash', 'scripts/check-local-health.sh'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
        return check_agent()
    except (subprocess.CalledProcessError, OSError, subprocess.TimeoutExpired):
        return False


def _quick_health() -> bool:
    try:
        health()
        return True
    except (LifecycleError, subprocess.CalledProcessError, OSError, subprocess.TimeoutExpired):
        return False


def _fresh_gate(state: dict) -> None:
    report = fresh_setup.collect(domain=state['domain'], ip=state['public_ipv4'], resume=False)
    if not report['ready_for_base_install']:
        raise LifecycleError('Fresh preflight blocked: ' + ', '.join(
            x['id'] for x in report['checks'] if x['status'] == 'block'))


def get_installed_identity() -> dict | None:
    if not instance.identity_path().exists():
        return None
    return instance.load()


def cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='DUC Lifecycle Manager 0.10.5 (single user entrypoint)')
    parser.add_argument('--status', action='store_true', help='show operation journal without changes')
    parser.add_argument('--dry-run', action='store_true', help='read-only operation detection')
    parser.add_argument('--repair', action='store_true', help='repair existing runtime services')
    public = parser.add_mutually_exclusive_group()
    public.add_argument('--public-plan', action='store_true', help='read-only DNS and HTTPS deployment plan')
    public.add_argument('--publish-panel', action='store_true', help='guarded panel A cutover after HTTPS routing test')
    public.add_argument('--publish-ns', action='store_true', help='guarded nameserver A cutover after real client field test')
    public.add_argument('--issue-cert-only', action='store_true', help='temporary ACME handoff, always restore services')
    public.add_argument('--issue-cert-dns01', action='store_true', help='Cloudflare DNS-01 certificate-only; existing services untouched')
    parser.add_argument('--client-verified', action='store_true', help='affirm successful real client field test for NS cutover')
    args = parser.parse_args(argv)
    if args.public_plan or args.publish_panel or args.publish_ns or args.issue_cert_only or args.issue_cert_dns01:
        from .public_activation import cli as public_cli
        choice = ('--cutover-panel' if args.publish_panel else '--cutover-ns' if args.publish_ns
                  else '--issue-cert' if args.issue_cert_only else '--issue-dns01' if args.issue_cert_dns01 else '--plan')
        public_args = [choice]
        if args.client_verified:
            public_args.append('--client-verified')
        if choice != '--plan' and (os.geteuid() != 0 or not sys.stdin.isatty()):
            print('Root and interactive terminal required for public activation.', file=sys.stderr)
            return 2
        return public_cli(public_args)
    try:
        repo = Path(__file__).resolve().parent.parent
        os.chdir(repo)
        release = read_version(repo / 'VERSION')
        if not release:
            raise LifecycleError('Missing source package VERSION')
        identity = get_installed_identity()
        installed = read_version(APP / 'VERSION')
        old = load_state()
        operation = decide(release, installed, identity, old, app_exists=(APP / 'duc/web.py').is_file())
        if args.status:
            print(json.dumps({'decision': operation, 'target_release': release, 'installed_release': installed,
                              'instance': {k: identity[k] for k in ('instance_id', 'domain', 'public_ipv4')} if identity else None,
                              'lifecycle': old}, indent=2, ensure_ascii=False))
            return 0
        if args.dry_run:
            print(f'MODE={operation.upper()} TARGET={release} INSTALLED={installed or "none"}; no changes')
            return 0
        if os.geteuid() != 0:
            raise LifecycleError('Run sudo bash install.sh for mutating operations')
        if not sys.stdin.isatty():
            raise LifecycleError('Interactive SSH terminal required; no automatic mutation in non-TTY mode')
        with exclusive_lock():
            # Re-check after lock, in case a previous installer just completed.
            old = load_state()
            identity = get_installed_identity()
            installed = read_version(APP / 'VERSION')
            operation = decide(release, installed, identity, old, app_exists=(APP / 'duc/web.py').is_file())
            if args.repair and identity and installed and version_tuple(installed) == version_tuple(release):
                operation = 'repair'
            if operation == 'repair' and not args.repair and _quick_health():
                print('LIFECYCLE: TUI / local runtime already healthy; no service restart.')
                state = old if old and old.get('instance_id') == identity['instance_id'] else new_state('repair', release, identity, {})
                state['operation'] = 'repair'
                state['release'] = release
                state['status'] = 'running'
                state['error'] = None
                write_state(state)
                onboard_web_certificate(state)
                tls_readiness(state)
                state['components'] = web_install.web_components(state['tls'], state['certificate'])
                complete = state['components']['web']['status'] == 'READY'
                state['outcome'] = 'READY' if complete else 'TUI_READY_WEB_INCOMPLETE'
                state['status'] = 'completed' if complete else 'partial'
                state['updated_utc'] = utc()
                write_state(state)
                print(f"LIFECYCLE: {state['outcome']} (TUI ready; Web status checked)")
                return 0
            if operation == 'resume':
                assert old is not None
                state = old
                print(f"RESUME {state['operation'].upper()} release={state['release']}, instance={state.get('instance_id')}")
            else:
                if operation == 'fresh':
                    print('=== FIRST INSTALL: read-only preflight and guided configuration ===')
                    opts = wizard_fresh()
                    op = 'fresh'
                elif operation == 'resume_fresh':
                    # From pre-lifecycle 0.10.1/0.10.2 interruption after identity creation.
                    assert identity
                    print('Partial instance detected; recovering with preserved domain/IP.')
                    opts = {'domain': identity['domain'], 'ip': identity['public_ipv4']}
                    op = 'fresh'
                elif operation == 'legacy_upgrade':
                    print('WARNING: existing pre-instance installation. Back up all secrets independently.')
                    opts = {}
                    op = 'legacy_upgrade'
                else:
                    opts = {}
                    op = operation
                state = new_state(op, release, identity, opts)
            print(f"PLAN: {state['operation'].upper()} to {release}; no Cloudflare writes, no DNS engine start/restart.")
            if state['operation'] == 'upgrade' or state['operation'] == 'legacy_upgrade':
                print('Upgrade snapshot restores app code and unit files only; apt/pip and upstream side effects are not transactional.')
            print('CONSEQUENCES: this operation may change local application files/services;')
            print('Cloudflare and the running DNS tunnel engine are not modified by lifecycle.')
            if not ask_yes_no(f"Continue with {state['operation'].upper()} to {release}?"):
                print('Cancelled; no lifecycle actions performed.')
                return 0
            write_state(state)
            try:
                execute(state, identity=identity, installed=installed, offer_web=True)
            except (Exception, KeyboardInterrupt) as exc:
                # Do not print internal exceptions verbatim, as subprocess exceptions
                # may contain values from commands in other future stages.
                state['error'] = {'kind': type(exc).__name__, 'step': next((
                    k for k, v in reversed(list(state['steps'].items())) if v['status'] == 'failed'), 'unknown'),
                    'at': utc()}
                state['status'] = 'failed'
                state['updated_utc'] = utc()
                write_state(state)
                print(f"ERROR: lifecycle stopped at {state['error']['step']}. See sudo bash install.sh --status.", file=sys.stderr)
                if state['operation'] in ('upgrade', 'legacy_upgrade') and state.get('backup') and (
                        state['steps'].get('apply', {}).get('status') in ('started', 'failed', 'completed') or
                        state['steps'].get('health', {}).get('status') in ('started', 'failed')):
                    print('Attempting code+unit rollback (leaving engine/Dante/MFA/Cloudflare untouched).', file=sys.stderr)
                    try:
                        rollback_code(Path(state['backup']))
                        state['status'] = 'failed_rolled_back'
                        for key in ('apply', 'health', 'tls_status'):
                            state['steps'].pop(key, None)
                        write_state(state)
                    except Exception as rb_exc:
                        print(f'Rollback failed: {type(rb_exc).__name__}; manual restore required.', file=sys.stderr)
                return 1
            return 0
    except (LifecycleError, instance.InstanceError, ValueError, OSError) as exc:
        print(f'LIFECYCLE: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(cli())
