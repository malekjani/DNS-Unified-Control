"""Optional Cloudflare A-record provisioner for an HTTPS admin panel.

Separate from the nine DNS NS delegations; never edits tunnel engine records.
"""
from __future__ import annotations

import argparse
import getpass
import sys

from .cloudflare_dns import CF, MARKER, ProvisionError, clean_domain, clean_ip, clean_label, decide, public_ip
from .catalog import LABELS
from .confirm import ask_yes_no


def panel_record(domain: str, ipv4: str, label: str = 'panel') -> dict:
    domain, ipv4, label = clean_domain(domain), clean_ip(ipv4), clean_label(label)
    # Deliberately do not put the panel inside any delegated tunnel name.
    if label in set(LABELS.values()) | {'ns'}:
        raise ProvisionError('Panel label conflicts with a tunnel delegation or authoritative NS')
    return {'type': 'A', 'name': f'{label}.{domain}', 'content': ipv4,
            'ttl': 120, 'proxied': False, 'comment': MARKER + ':admin-https'}


def apply_panel(client, domain: str, ipv4: str, label: str = 'panel', dry_run: bool = False) -> dict:
    rec = panel_record(domain, ipv4, label)
    zone = client.zone(clean_domain(domain))
    action, record_id = decide(client.records(zone, rec['name']), rec)
    if not dry_run:
        if action == 'create':
            client.call('POST', f'/zones/{zone}/dns_records', rec)
        elif action == 'update':
            client.call('PATCH', f'/zones/{zone}/dns_records/{record_id}', rec)
    return {'action': action, 'name': rec['name'], 'type': rec['type'],
            'content': rec['content'], 'proxied': False}


def main(argv=None):
    p = argparse.ArgumentParser(description='Create a separate Cloudflare DNS-only A record for the web panel')
    p.add_argument('--domain', required=True)
    p.add_argument('--ip', help='Public VPS IPv4 (autodetect if omitted)')
    p.add_argument('--label', default='panel')
    p.add_argument('--dry-run', action='store_true')
    args = p.parse_args(argv)
    try:
        rec = panel_record(args.domain, args.ip or public_ip(), args.label)
        print(f'Panel: {rec["name"]}  A {rec["content"]}  (DNS only, NOT NS-delegated)')
        token = getpass.getpass('Cloudflare Zone-scoped API Token (hidden, not stored): ').strip()
        if not token:
            raise ProvisionError('API token required')
        client = CF(token)
        if not args.dry_run and not ask_yes_no('Create/update this Cloudflare panel A record?'):
            print('Cancelled: no changes made')
            return 2
        result = apply_panel(client, args.domain, rec['content'], args.label, dry_run=args.dry_run)
        print(('WOULD ' if args.dry_run else '') + result['action'].upper() + ': ' + result['name'])
        print('No tunnel NS records were modified.')
        return 0
    except (ProvisionError, EOFError, KeyboardInterrupt) as e:
        print(f'Panel DNS error: {e or "interrupted"}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
