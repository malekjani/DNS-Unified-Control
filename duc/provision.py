"""Resumable, opt-in server provisioner for all exclusive DNS tunnel engines.

One installation path for upgrades and fresh installs.  No engine is started,
no resolver/firewall/Cloudflare configuration is mutated, and a running binary
is never replaced. Status describes installation AND readiness separately.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import pathlib
import secrets
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass

from . import core, worker
from .catalog import ENGINES, BINARIES

REPORT = core.STATE / 'provision-report.json'
LOCK = core.STATE / 'provision.lock'
MB = 1024 * 1024


@dataclass(frozen=True)
class Strategy:
    kind: str
    description: str
    heavyweight: bool = False


# A single registry is the source of truth for batch installation behavior.
STRATEGIES = {
    'master': Strategy('go', 'Upstream Go source, matching server TOML and shared key'),
    'slipstream': Strategy('consent', 'Pinned AliRezaBeigy binaries; install from authenticated web panel or scripts/install-slipstream-ali.sh (no terminal yes).', True),
    'dnstt': Strategy('go', 'Upstream Go source and Noise keypair'),
    'noizdns': Strategy('go', 'anonvector/dnstt fork server; TXT/NoizDNS-compatible DNS; dedicated binary + Noise keypair'),
    'vaydns': Strategy('go', 'Upstream Go source and Noise keypair'),
    'soar': Strategy('go', 'Upstream Go source; unauthenticated public-proxy mode is disabled'),
    'iodine': Strategy('apt', 'Ubuntu iodine package and locally protected password'),
    'dns2tcp': Strategy('apt', 'Ubuntu dns2tcp package and locally protected shared key'),
    'xdns': Strategy('review', 'Xray FinalMask requires an audited native Xray configuration'),
}
assert set(STRATEGIES) == set(ENGINES)


def command(args, *, timeout=600, cwd=None, env=None):
    return worker.run(list(args), cwd=cwd, timeout=timeout, env=env)


def create_secret(path: pathlib.Path, length=32):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.exists():
        if not path.is_file() or not path.stat().st_size:
            raise RuntimeError(f'Existing secret needs manual inspection: {path}')
        # Repair overly permissive mode without changing content.
        path.chmod(0o600)
        return False
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(secrets.token_hex(length // 2) + '\n')
            f.flush()
            os.fsync(f.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return True


def configure_master(source_root: pathlib.Path):
    sample = source_root / 'server_config.toml.simple'
    if not sample.is_file():
        raise RuntimeError('MasterDnsVPN upstream server_config.toml.simple missing')
    target = core.ROOT / 'engines/master/base.toml'
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not target.exists():
        # Replace shipped example domain only in the rendered server file (runner).
        # Disable unused external SOCKS credentials in our saved base template.
        from .runner import replace_keys, write_secure
        content = replace_keys(sample.read_text(), {
            'USE_EXTERNAL_SOCKS5': False, 'SOCKS5_AUTH': False,
            'SOCKS5_PASS': '', 'PROTOCOL_TYPE': 'SOCKS5',
        })
        write_secure(target, content)
    elif not target.is_file() or not target.stat().st_size:
        raise RuntimeError('Existing Master base.toml is invalid; manual repair required')
    create_secret(core.ROOT / 'keys/master.key', length=64)


def prepare(engine: str):
    if engine == 'master':
        folder = core.STATE / 'upstream-src/master'
        if not folder.is_dir():
            raise RuntimeError('Master source unavailable after build')
        configure_master(folder)
    elif engine in ('dnstt', 'noizdns', 'vaydns'):
        worker.generate_key(engine)
    elif engine == 'soar':
        from . import soar_secure
        soar_secure.ensure_keys()
    elif engine == 'iodine':
        create_secret(core.ROOT / 'keys/iodine.pass', length=32)
    elif engine == 'dns2tcp':
        create_secret(core.ROOT / 'keys/dns2tcp.key', length=48)
    elif engine == 'slipstream':
        script = pathlib.Path('/opt/dns-unified-control/scripts/prepare-slipstream-rust.sh')
        if not script.is_file():
            raise RuntimeError('SlipStream certificate preparation script missing')
        command(['bash', str(script)], timeout=30)


def resources():
    import psutil
    return {'ram_available': psutil.virtual_memory().available,
            'swap_total': psutil.swap_memory().total,
            'disk_free': shutil.disk_usage('/').free}


def toolchain():
    # Initial preflight done once, and only when necessary; do not run apt for
    # a second time merely because an installed engine was skipped.
    packages=[]
    for executable, package in [('git','git'), ('go','golang-go'),
                                 ('gcc','build-essential'), ('openssl','openssl')]:
        if shutil.which(executable) is None: packages.append(package)
    if packages:
        command(['apt-get','update'], timeout=300)
        env=dict(os.environ, DEBIAN_FRONTEND='noninteractive')
        command(['apt-get','install','-y','--no-install-recommends', *packages],
                timeout=600, env=env)


def install_go(engine):
    # worker source cache is reused across reruns. Never call this on an active
    # service, and never install into its executable path on a failing build.
    return worker.install_server_raw(engine)


def install_apt(engine):
    package = {'iodine':'iodine','dns2tcp':'dns2tcp'}[engine]
    env=dict(os.environ, DEBIAN_FRONTEND='noninteractive')
    command(['apt-get','install','-y','--no-install-recommends', package],
            timeout=420, env=env)
    prepare(engine)
    return {'message':f'Ubuntu package {package} installed'}


def install_rust(engine):
    raise RuntimeError('Rust source build disabled; use the pinned AliRezaBeigy importer with yes confirmation')


def readiness(engine):
    try: return core.check_ready(engine)
    except Exception as e: return {'ready':False,'issues':[f'Preflight error: {type(e).__name__}'],'binary':''}


def observe(engine, *, dry_run=False, include_heavy=False):
    strategy=STRATEGIES[engine]
    binary=shutil.which(BINARIES[engine])
    live=core.is_active(engine)
    first={'engine':engine,'strategy':strategy.kind,'binary':binary or '',
           'running':live,'readiness':readiness(engine), 'time':int(time.time())}
    if live:
        return dict(first,state='preserved-running',message='Running engine preserved; not rebuilt or stopped')
    if strategy.kind=='review':
        # Existing executable may be recognized but cannot be made wire-compatible
        # without an audited adapter or protocol config.
        if binary:
            return dict(first,state='present-needs-review',message=strategy.description)
        return dict(first,state='requires-review',message=strategy.description)
    if engine=='slipstream':
        from . import slipstream_ali
        try:
            for kind,info in slipstream_ali.BINARIES.items():
                slipstream_ali.check_binary(info['target'],kind,cli=False)
        except (OSError,RuntimeError) as err:
            return dict(first,state='requires-consent',
                        message='Import from web workflow or bash scripts/install-slipstream-ali.sh; '
                        +str(err)[:180])
        r=readiness(engine)
        return dict(first,state='present-ready' if r['ready'] else 'installed-needs-config',
                    readiness=r,message='Pinned AliRezaBeigy release verified; Exclusive Mode only')
    if engine=='noizdns' and binary:
        from .noiz_provenance import check as provenance_check
        if not provenance_check(binary):
            if dry_run:
                return dict(first,state='would-rebuild',message='NoizDNS source/hash not verified; rebuild from anonvector/dnstt')
            rsrc=install_go(engine)
            r=readiness(engine)
            return dict(first,state='installed-ready' if r['ready'] else 'installed-needs-config',
                        readiness=r,binary=shutil.which(BINARIES[engine]) or '',
                        source_commit=rsrc.get('source_commit',''),
                        message='Replaced unverified NoizDNS binary with tracked anonvector/dnstt build')
    if binary and first['readiness']['ready']:
        return dict(first,state='present-ready',message='Already installed and ready; skipped')
    if dry_run:
        state=('deferred-heavy' if strategy.heavyweight and not include_heavy and not binary
               else 'would-configure' if binary else 'would-install')
        return dict(first,state=state,message=strategy.description)
    if strategy.heavyweight and not include_heavy and not binary:
        return dict(first,state='deferred-heavy',message='Rust build disabled on small VPS by default; use --include-heavy after reviewing resources')
    # If binary is installed, repair only missing configuration/keys and preserve it.
    if binary:
        if engine=='master':
            src=core.STATE/'upstream-src/master'
            if src.exists():prepare('master')
            else:raise RuntimeError('Master binary exists but original source/template is missing; do not guess config')
        else:prepare(engine)
        r=readiness(engine)
        return dict(first,state='configured-ready' if r['ready'] else 'installed-needs-config',
                    readiness=r,message='Existing binary preserved; preflight rechecked')
    if strategy.kind=='go':
        rsrc=install_go(engine)
        if engine=='master':prepare(engine)
        result_meta={'source_commit':rsrc.get('source_commit','')}
    elif strategy.kind=='apt':
        install_apt(engine)
        result_meta={}
    else:
        raise RuntimeError('Unsupported install strategy')
    r=readiness(engine)
    return dict(first,state='installed-ready' if r['ready'] else 'installed-needs-config',
                binary=shutil.which(BINARIES[engine]) or '',readiness=r,
                message='Installed without activating; verify config and client separately',**result_meta)


def report_data():
    try: return json.loads(REPORT.read_text())
    except (OSError, ValueError, TypeError):return {}


def execute(*, only=ENGINES, dry_run=False, include_heavy=False, skip_toolchain=False):
    if os.geteuid()!=0 and not dry_run:
        raise PermissionError('Run as root (sudo), because installing binaries requires privileges')
    if dry_run:
        return {'version':'0.9.8','dry_run':True,'engines':{
            e: observe(e,dry_run=True,include_heavy=include_heavy) for e in only}}
    core.STATE.mkdir(parents=True,exist_ok=True)
    with LOCK.open('a+') as lock:
        try:fcntl.flock(lock.fileno(),fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:raise RuntimeError('Provisioning already running; see provision.lock')
        # Captures actual results, not a partial JSON assembled by string append.
        report={'version':'0.9.8','started':int(time.time()),'completed':None,
                'engines':report_data().get('engines',{}), 'active_before':core.list_active()}
        core.atomic_json(REPORT,report)
        if not skip_toolchain:
            toolchain()
        for engine in only:
            try:
                entry=observe(engine,include_heavy=include_heavy)
            except Exception as exc:
                entry={'engine':engine,'state':'failed','message':f'{type(exc).__name__}: {str(exc)[:400]}',
                       'binary':shutil.which(BINARIES[engine]) or '',
                       'readiness':readiness(engine),'time':int(time.time())}
            report['engines'][engine]=entry
            core.atomic_json(REPORT,report)
            print(f"{engine:<12} {entry['state']:<24} {entry.get('message','')}",flush=True)
        report['completed']=int(time.time())
        report['active_after']=core.list_active()
        core.atomic_json(REPORT,report)
        if report['active_after']!=report['active_before']:
            raise RuntimeError('Active engine set changed during provisioning; inspect systemd')
        return report


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dry-run',action='store_true',help='inspect without installing or writing')
    parser.add_argument('--include-heavy',action='store_true',help='legacy option; SlipStream always requires separate yes confirmation')
    parser.add_argument('--only',choices=ENGINES,action='append',help='limit to these engines')
    parser.add_argument('--skip-toolchain',action='store_true',help='do not apt-install missing Go/Git tools')
    parser.add_argument('--report',action='store_true',help='print last persisted report')
    args=parser.parse_args(argv)
    if args.report:
        print(json.dumps(report_data(),indent=2));return 0
    try:
        results=execute(only=tuple(args.only or ENGINES),dry_run=args.dry_run,
                        include_heavy=args.include_heavy,skip_toolchain=args.skip_toolchain)
    except (RuntimeError,PermissionError,subprocess.SubprocessError) as err:
        print('PROVISION ERROR:',err,file=sys.stderr);return 2
    if args.dry_run:print(json.dumps(results,indent=2))
    else:
        print('Report:',REPORT)
        print('Active engine preserved:',', '.join(results['active_after']) or 'none')
        print('Installed != tunnel verified. Never assume all engines are wire-compatible.')
    return 1 if any(results['engines'][e]['state']=='failed' for e in (args.only or ENGINES)) else 0


if __name__=='__main__':
    sys.exit(main())
