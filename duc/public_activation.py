"""Public onboarding workflow for an existing DUC instance.

Never modifies DNS or services in the default plan mode. Explicit steps are
required for DNS cutover and temporary ACME certificate-only handoff. A cert
alone does NOT mean the public HTTPS listener is correctly routed.
"""
from __future__ import annotations

import argparse
import getpass
import json
from pathlib import Path
import re
import subprocess
from typing import Any

from . import instance
from .confirm import ask_yes_no


class PublicActivationError(RuntimeError):
    pass


def port_owners(ss_output: str) -> dict[str, list[str]]:
    """Parse ss -ltnp output conservatively; unrecognized owners stay visible."""
    result: dict[str, list[str]] = {'80': [], '443': []}
    for line in ss_output.splitlines():
        columns = line.split(None, 5)
        if len(columns) < 5:
            continue
        local = columns[3] if columns[0] in ('LISTEN', 'ESTAB') else columns[4]
        match = re.search(r':(80|443)$', local)
        if not match:
            continue
        port = match.group(1)
        names = re.findall(r'\("([^"\n]+)"\s*,\s*pid=', line)
        for name in names or ['unknown']:
            if name not in result[port]:
                result[port].append(name)
    return result


def read_listeners() -> dict[str, list[str]]:
    try:
        proc = subprocess.run(['ss', '-H', '-ltnp'], capture_output=True, text=True,
                              check=True, timeout=8)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise PublicActivationError('Cannot inspect TCP listeners; no public mutation allowed') from exc
    return port_owners(proc.stdout)


def routing_mode(owners: dict[str, list[str]]) -> str:
    # Caddy alone owning both ports is a potential path, not proof of cert validation.
    other443 = [p for p in owners['443'] if p != 'caddy']
    if other443:
        return 'REVERSE_PROXY_ROUTING_REQUIRED'
    if not owners['443'] or owners['443'] == ['caddy']:
        return 'HTTPS_PORT_AVAILABLE_OR_CADDY'
    return 'INSPECT_HTTPS_OWNER'


def plan(identity: dict, owners: dict[str, list[str]]) -> dict[str, Any]:
    return {
        'instance_id': identity['instance_id'],
        'fqdn': identity['panel_fqdn'],
        'nameserver_fqdn': identity['nameserver_fqdn'],
        'target_ipv4': identity['public_ipv4'],
        'listeners': owners,
        'https_route': routing_mode(owners),
        'cloudflare_token': 'PROMPT_WHEN_NEEDED_NOT_STORED',
        'dns_cutover': 'REQUIRES_EXPLICIT_YES',
        'tls_certificate': 'NOT_EQUIVALENT_TO_HTTPS_ROUTING',
        'engine_ns_cutover': 'REQUIRES_INDEPENDENT_CLIENT_FIELD_TEST',
        'status': 'PUBLIC_ACTIVATION_PENDING',
    }


def _health_gate() -> None:
    # Guard against DNS cutover before local base installation is healthy.
    from .lifecycle import health
    health()


def verify_local_panel_https(fqdn: str) -> bool:
    """Validate trusted certificate AND DUC page through local SNI :443.

    This is a pre-cutover test; never disables certificate verification.
    """
    try:
        result = subprocess.run(
            ['curl', '--noproxy', '*', '-fsS', '--connect-timeout', '3', '--max-time', '9',
             '--resolve', f'{fqdn}:443:127.0.0.1', f'https://{fqdn}/'],
            check=False, capture_output=True, text=True, timeout=11)
        return result.returncode == 0 and '<title>DNS Unified Control</title>' in result.stdout
    except (OSError, subprocess.TimeoutExpired):
        return False


def cutover(identity: dict, label: str, *, client_verified: bool = False,
            token: str | None = None, input_fn=None, output=print) -> str:
    """Update only the desired managed A record. Cloudflare token never persisted."""
    from .cloudflare_dns import CF, MARKER
    from .fresh_setup import valid_public_ip
    if label not in ('panel', 'ns'):
        raise PublicActivationError('Only panel and ns A records may be migrated')
    if label == 'ns' and not client_verified:
        raise PublicActivationError('NS cutover requires --client-verified after a real client field test')
    _health_gate()
    domain = identity['domain']
    fqdn = f'{label}.{domain}'
    dest = identity['public_ipv4']
    if input_fn is None:
        input_fn = input
    if token is None:
        token = getpass.getpass('Cloudflare DNS Edit API token (hidden, never saved): ').strip()
    if not token:
        raise PublicActivationError('Cloudflare DNS Edit API token is required')
    cf = CF(token)
    zone = cf.zone(domain)
    rows = cf.records(zone, fqdn)
    matches = [r for r in rows if r.get('name', '').rstrip('.').lower() == fqdn]
    if len(matches) != 1 or matches[0].get('type') != 'A':
        raise PublicActivationError('Expected exactly one matching A record; no changes made')
    record = matches[0]
    if record.get('proxied') is not False:
        raise PublicActivationError('Record must be DNS-only for safe cutover')
    if MARKER not in (record.get('comment') or ''):
        raise PublicActivationError('Existing A record is not DUC-managed; inspect in Cloudflare before changing')
    try:
        old_ip = valid_public_ip(record.get('content', ''))
    except ValueError as exc:
        raise PublicActivationError('Existing record is not a valid public IPv4') from exc
    if old_ip == dest:
        output(f'UNCHANGED: {fqdn} already points to {dest}')
        return 'unchanged'
    output(f'CUTOVER: {fqdn} A {old_ip} -> {dest}')
    output('The old VPS should remain online. NS delegation records will not be modified.')
    if label == 'panel':
        # Existing Xray/HAProxy can serve the panel through SNI routing; a
        # running Caddy process is not required. Demand actual valid TLS and
        # the correct DUC response before migrating the production hostname.
        if not verify_local_panel_https(fqdn):
            raise PublicActivationError('Panel cutover blocked: valid TLS routing to the DUC login page is not yet verified on local :443')
    else:
        output('WARNING: switching ns moves all delegated DNS tunnel traffic to this VPS.')
        output('New keys may require new client packages; do not assume old clients remain compatible.')
    if not ask_yes_no(f'Apply {label} A record change now?', input_fn=input_fn, output=output):
        return 'cancelled'
    if label == 'ns' and not ask_yes_no('Have you completed real client testing on this exact new VPS?',
                      input_fn=input_fn, output=output):
        return 'cancelled'
    # Snapshot metadata before write, private journal; avoid any API token in this file.
    from datetime import datetime, timezone
    import os
    from pathlib import Path
    root = Path('/var/lib/dns-unified/lifecycle')
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(root, 0o700)
    name = root / ('dns-cutover-' + label + '-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ') + '.json')
    fd = os.open(name, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w', encoding='utf8') as f:
        json.dump({'fqdn': fqdn, 'record_id': record['id'], 'old_ip': old_ip,
                   'new_ip': dest, 'status': 'before-update'}, f)
    cf.call('PATCH', f'/zones/{zone}/dns_records/{record["id"]}', {'content': dest})
    after = [r for r in cf.records(zone, fqdn) if r.get('type') == 'A' and r.get('name') == fqdn]
    if len(after) != 1 or after[0].get('content') != dest:
        raise PublicActivationError(f'Remote DNS update not verified! Manual rollback to {old_ip} may be needed.')
    output(f'VERIFIED: {fqdn} -> {dest}. Rollback target: {old_ip}')
    return 'updated'


def cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='DUC public activation, guarded separately from install')
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--plan', action='store_true', help='read-only readiness and port ownership')
    modes.add_argument('--cutover-ns', action='store_true', help='move tunnel NS target after client tests')
    modes.add_argument('--cutover-panel', action='store_true', help='move panel A record only after local HTTPS verification')
    modes.add_argument('--issue-cert', action='store_true', help='temporary HTTP-01 cert-only handoff, restores services')
    modes.add_argument('--issue-dns01', action='store_true', help='DNS-01 cert-only via one-time Cloudflare token, no port conflict')
    parser.add_argument('--client-verified', action='store_true', help='assert external DNS+SOCKS field test was completed')
    args = parser.parse_args(argv)
    try:
        identity = instance.load()
        if args.cutover_ns:
            cutover(identity, 'ns', client_verified=args.client_verified)
        elif args.cutover_panel:
            cutover(identity, 'panel')
        elif args.issue_dns01:
            subprocess.run(['bash', 'scripts/cert-cloudflare-dns01.sh', identity['panel_fqdn']], check=True)
        elif args.issue_cert:
            # certificate-only path, never announces public HTTPS READY
            subprocess.run(['bash', 'scripts/cert-standalone-handoff.sh', identity['panel_fqdn'],
                            identity['public_ipv4']], check=True)
        else:
            print(json.dumps(plan(identity, read_listeners()), indent=2, ensure_ascii=False))
        return 0
    except (PublicActivationError, subprocess.CalledProcessError, OSError, ValueError,
            EOFError, KeyboardInterrupt) as exc:
        print(f'PUBLIC_ACTIVATION_NOT_COMPLETE: {type(exc).__name__}: {exc}', file=__import__('sys').stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(cli())
