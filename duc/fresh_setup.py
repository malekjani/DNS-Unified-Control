"""Read-only first-run assessor and guarded profile initialization.

No DNS API calls, network writes, firewall mutations or engine starts occur here.
Web and TUI can consume `--audit --json` without parsing human messages.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

MIB = 1024 * 1024
GIB = 1024 * MIB
DOMAIN_RE = re.compile(r'^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$')


def valid_domain(name: str) -> str:
    name = name.strip().lower().rstrip('.')
    if not DOMAIN_RE.fullmatch(name):
        raise ValueError('Invalid base domain')
    return name


def valid_public_ip(address: str) -> str:
    address = address.strip()
    try:
        ip = ipaddress.ip_address(address)
        if not isinstance(ip, ipaddress.IPv4Address) or not ip.is_global:
            raise ValueError('Public IPv4 required')
    except ValueError as e:
        raise ValueError('Public IPv4 required') from e
    return str(ip)


def parse_os_release(text: str) -> dict[str, str]:
    result = {}
    for line in text.splitlines():
        if '=' in line and not line.lstrip().startswith('#'):
            key, value = line.split('=', 1)
            result[key.strip()] = value.strip().strip('"\'')
    return result


def parse_meminfo(text: str) -> dict[str, int]:
    out = {}
    for line in text.splitlines():
        match = re.match(r'^([A-Za-z_()]+):\s+(\d+)\s+kB', line)
        if match:
            out[match.group(1)] = int(match.group(2)) * 1024
    return out


def parse_ss_udp53(text: str) -> list[str]:
    found = []
    for line in text.splitlines():
        columns = line.split()
        if len(columns) < 4:
            continue
        # Output from `ss -H -lun`: State Recv-Q Send-Q Local Peer.
        local = columns[3]
        if local.rsplit(':', 1)[-1] == '53':
            found.append(local)
    return found


def parse_ss_tcp(text: str) -> dict[int, list[str]]:
    occupied = {1080: [], 8088: [], 80: [], 443: []}
    for line in text.splitlines():
        cols = line.split()
        if len(cols) < 4:
            continue
        endpoint = cols[3]
        try:
            port = int(endpoint.rsplit(':', 1)[-1])
        except ValueError:
            continue
        if port in occupied:
            occupied[port].append(endpoint)
    return occupied


def safe_call(args: list[str], timeout: int = 6) -> tuple[int, str]:
    try:
        completed = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
        return completed.returncode, completed.stdout
    except (OSError, subprocess.TimeoutExpired):
        return 127, ''


def collect(*, domain: str | None = None, ip: str | None = None, resume: bool = False,
            os_text: str | None = None, mem_text: str | None = None,
            disk_free: int | None = None, port_text: str | None = None, tcp_text: str | None = None,
            existing: bool | None = None, systemd: bool | None = None,
            apt: bool | None = None) -> dict:
    """Return factual checks and a plan. Injected values allow offline tests."""
    domain = valid_domain(domain) if domain else None
    if ip is not None:
        ip = valid_public_ip(ip)
    if os_text is None:
        try: os_text = Path('/etc/os-release').read_text()
        except OSError: os_text = ''
    osinfo = parse_os_release(os_text)
    if mem_text is None:
        try: mem_text = Path('/proc/meminfo').read_text()
        except OSError: mem_text = ''
    mem = parse_meminfo(mem_text)
    if disk_free is None: disk_free = shutil.disk_usage('/').free
    ss_ok = True
    if port_text is None:
        ss_code, port_text = safe_call(['ss', '-H', '-lun'])
        ss_ok = ss_code == 0
    tcp_ok = True
    if tcp_text is None:
        tcp_rc, tcp_text = safe_call(['ss', '-H', '-ltn'])
        tcp_ok = tcp_rc == 0
    if existing is None:
        config_root = Path('/etc/dns-unified')
        existing = (Path('/opt/dns-unified-control/duc/web.py').exists() or
                    (config_root.is_dir() and any(config_root.iterdir())) or
                    Path('/var/lib/dns-unified/mfa/web-mfa.json').exists())
    if systemd is None: systemd = bool(shutil.which('systemctl') and Path('/run/systemd/system').exists())
    if apt is None: apt = bool(shutil.which('apt-get'))

    checks = []
    def put(key, level, message, next_step):
        checks.append({'id': key, 'status': level, 'message': message, 'remedy': next_step})
    distro = osinfo.get('ID', '').lower()
    tested = {'ubuntu': {'24.04'}, 'debian': {'12', '13'}}
    version = osinfo.get('VERSION_ID', '')
    if version not in tested.get(distro, set()):
        put('os', 'block', f'Unsupported or untested OS: {distro or "unknown"} {version or "unknown"}',
            'Use an explicitly tested release: Ubuntu 24.04 LTS or Debian 12/13.')
    else:
        put('os', 'pass', f'{distro} {version}', '')
    put('systemd', 'pass' if systemd else 'block', 'systemd runtime available' if systemd else 'systemd not available',
        '' if systemd else 'Use a normal systemd-based VPS, not a container without systemd.')
    put('apt', 'pass' if apt else 'block', 'apt-get present' if apt else 'apt-get missing',
        '' if apt else 'Only Debian/Ubuntu apt installation is supported.')
    if existing:
        put('existing_install', 'warn' if resume else 'block', 'DUC state/configuration already exists',
            'Use --resume only to continue the SAME fresh installation; do not overwrite a live VPS.')
    else:
        put('existing_install', 'pass', 'No existing DUC installation detected', '')
    if disk_free < 3 * GIB:
        put('disk', 'block', f'{disk_free // MIB} MiB free on root volume', 'Free at least 3 GiB before installing; larger toolchains need more.')
    else:
        put('disk', 'warn' if disk_free < 7 * GIB else 'pass', f'{disk_free // MIB} MiB free on root volume',
            'Prefer 7+ GiB free for building multiple engines.' if disk_free < 7 * GIB else '')
    total_mem = mem.get('MemTotal', 0)
    swap = mem.get('SwapTotal', 0)
    if total_mem and total_mem < 512 * MIB and swap < 1024 * MIB:
        put('memory', 'block', f'{total_mem // MIB} MiB RAM, {swap // MIB} MiB swap',
            'Provision RAM or swap with operator approval before Go source builds.')
    else:
        put('memory', 'warn' if total_mem and total_mem < 1024 * MIB and swap < 1024 * MIB else 'pass',
            f'{total_mem // MIB} MiB RAM, {swap // MIB} MiB swap',
            'Add swap after reviewing free disk before building engines.' if total_mem < 1024 * MIB and swap < 1024 * MIB else '')
    p53 = parse_ss_udp53(port_text)
    if not ss_ok:
        put('udp53', 'warn', 'UDP/53 listener could not be inspected (ss missing or failed)',
            'Installer supplies iproute2; re-run sudo ss -lunp after bootstrap and before starting an engine.')
    elif p53:
        # Local systemd-resolved stubs are normal at bootstrap and do not
        # prevent the panel/Agent from being installed (engines stay stopped).
        # Public/wildcard listeners must be resolved before DNS activation.
        loopback = all(x.startswith(('127.', '[::1]:', '::1:', '[::ffff:127.')) for x in p53)
        put('udp53', 'warn' if loopback else 'block',
            ('Loopback DNS stub on UDP/53: ' if loopback else 'Non-loopback UDP/53 listener detected: ') + ', '.join(p53),
            ('System resolver stub: installation can proceed, but inspect sudo ss -lunp '
             'and safeguard resolv.conf before changing the stub or starting any DNS engine.' if loopback else
             'Conflict with future DNS engine: inspect owner; do not start UDP/53 engine until resolved.'))
    else:
        put('udp53', 'pass', 'UDP/53 not currently occupied', '')
    if not tcp_ok:
        put('tcp_listeners', 'warn', 'TCP port listeners not inspected (ss missing/failed)',
            'Re-check 1080 and 8088 before installation.')
    else:
        ports = parse_ss_tcp(tcp_text)
        for port in (8088, 1080):
            if ports[port]:
                put(f'tcp_{port}', 'block', f'TCP/{port} already in use: {", ".join(ports[port])}',
                    'Stop/relocate the conflicting service BEFORE installing the DUC panel/Dante.')
        if ports[80] or ports[443]:
            put('https_ports', 'warn', 'TCP/80 or 443 already occupied',
                'Inspect with sudo ss -ltnp. Public HTTPS is deferred until separate approval.')
    put('public_ip', 'pass' if ip else 'warn', f'Intended VPS IP: {ip}' if ip else 'VPS IPv4 not supplied',
        '' if ip else 'Supply --ip from the hosting provider before DNS cutover.')
    checks.append({'id': 'fresh_identity', 'status': 'warn',
                   'message': 'Fresh keys, Dante credentials and TOTP will differ from old VPS',
                   'remedy': (f'Regenerate/redeploy every client package BEFORE changing ns.{domain}.' if domain else
                              'New server keys require rebuilding all client packages before switching existing DNS.')})
    checks.append({'id': 'independent_access', 'status': 'warn',
                   'message': 'Out-of-band SSH/console and cloud firewall cannot be verified locally',
                   'remedy': 'Verify IP-based SSH, console recovery, UDP/53 and TCP/80/443 in provider firewall.'})
    actions = [
        {'id': 'preflight', 'operation': 'read-only audit', 'automatic': True},
        {'id': 'base', 'operation': 'install dashboard, Agent, mandatory Soar/NoizDNS and fresh keys', 'automatic': True},
        {'id': 'dante', 'operation': 'install a single localhost authenticated Dante', 'automatic': True},
        {'id': 'profiles', 'operation': f'write local engine domains under {domain or "selected domain"}', 'automatic': True},
        {'id': 'other_engines', 'operation': 'provision additional missing engines with explicit --with-engines', 'automatic': False},
        {'id': 'clients', 'operation': 'build and test NEW native/SlipNet clients against NEW server IPv4', 'automatic': False},
        {'id': 'panel_dns', 'operation': 'cut over panel A record after HTTP readiness', 'automatic': False},
        {'id': 'https', 'operation': 'enable Caddy after panel DNS cutover and test MFA', 'automatic': False},
        {'id': 'ns_dns', 'operation': 'cut over ns A record only after tunnel + client proof', 'automatic': False},
        {'id': 'rollback', 'operation': 'keep old VPS online and provide reverse guarded DNS changes', 'automatic': False},
    ]
    blocked = [x['id'] for x in checks if x['status'] == 'block']
    for action in actions:
        action['state'] = ('blocked' if blocked else 'ready') if action['automatic'] else 'pending-operator'
    return {'schema': 'duc.fresh-preflight.v1', 'mode': 'fresh-resume' if resume else 'fresh',
            'domain': domain, 'intended_ip': ip,
            'ready_for_base_install': not blocked,
            'checks': checks, 'actions': actions,
            'policy': {'dns_mutation_during_install': False, 'start_dns_engine_during_install': False,
                       'restore_old_credentials': False, 'auto_modify_resolv_conf': False}}


def configure_domains(domain: str) -> dict:
    """Set only domain fields for an inactive installation, without importing old secrets."""
    if os.geteuid() != 0:
        raise RuntimeError('Root required')
    domain = valid_domain(domain)
    from . import core
    from .catalog import ENGINES, LABELS
    if core.list_active():
        raise RuntimeError('DNS engine active: refusing fresh profile initialization')
    path = core.ROOT / 'profiles.json'
    data = core.profiles()
    for engine in ENGINES:
        previous = data[engine]['domain']
        wanted = f'{LABELS[engine]}.{domain}'
        if previous != wanted and not previous.endswith('.example.com'):
            raise RuntimeError(f'{engine}: existing non-default domain; refusing overwrite')
        data[engine]['domain'] = wanted
    core.atomic_json(path, data)
    return {'ok': True, 'base_domain': domain,
            'domains': {engine: data[engine]['domain'] for engine in ENGINES},
            'dns_records_mutated': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description='Safe fresh VPS preflight for DNS Unified Control')
    parser.add_argument('action', choices=('audit', 'profiles'))
    parser.add_argument('--domain', help='Optional for a read-only initial audit; required for profiles')
    parser.add_argument('--ip', default=None)
    parser.add_argument('--resume', action='store_true')
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--gate', action='store_true', help='exit 2 when a blocking check exists')
    args = parser.parse_args(argv)
    try:
        if args.action == 'profiles':
            if not args.domain:
                parser.error('profiles requires --domain')
            print(json.dumps(configure_domains(args.domain), indent=2))
            return 0
        report = collect(domain=args.domain, ip=args.ip, resume=args.resume)
        if args.json:
            print(json.dumps(report, ensure_ascii=False, indent=2))
        else:
            print(f'Fresh VPS assessment — {report["domain"] or "unconfigured host"} — ' + ('READY' if report['ready_for_base_install'] else 'BLOCKED'))
            for entry in report['checks']:
                print(f'[{entry["status"].upper():5}] {entry["id"]}: {entry["message"]}')
                if entry['remedy']:
                    print('         ', entry['remedy'])
            print('Install never edits Cloudflare or enables UDP/53. NEW identity requires NEW client packages.')
        return 2 if args.gate and not report['ready_for_base_install'] else 0
    except (ValueError, RuntimeError, OSError) as error:
        print(f'Fresh preflight: {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
