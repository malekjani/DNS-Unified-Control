"""Small read-only helpers for DUC's step-by-step initial installation.

The Cloudflare API token is obtained with getpass inside this process, only used
for read operations, never passed in argv/env, printed, or persisted to disk.
"""
from __future__ import annotations
import argparse
import getpass
import sys
from .fresh_setup import valid_domain, valid_public_ip


def verify_cloudflare(domain: str, *, prompt=getpass.getpass, client_type=None) -> bool:
    from .cloudflare_dns import CF, ProvisionError
    domain = valid_domain(domain)
    token = prompt('Cloudflare API Token (hidden, never saved): ').strip()
    if not token:
        print('Cloudflare token not supplied; integration deferred (no DNS changes).')
        return False
    try:
        client = (client_type or CF)(token)
        # Only GET requests; verify active zone and Zone Read permission.
        client.zone(domain)
    except ProvisionError as exc:
        print(f'Cloudflare read-only verification failed: {exc}', file=sys.stderr)
        return False
    finally:
        token = None
    print(f'Cloudflare: verified access to active zone {domain}. No records were changed. Token NOT saved.')
    return True


def main(argv=None):
    parser=argparse.ArgumentParser(description='Read-only DUC guided setup validators')
    sub=parser.add_subparsers(dest='cmd', required=True)
    cloudflare=sub.add_parser('verify-cloudflare')
    cloudflare.add_argument('--domain', required=True)
    valid=sub.add_parser('validate')
    valid.add_argument('--domain', required=True)
    valid.add_argument('--ip', required=True)
    args=parser.parse_args(argv)
    try:
        if args.cmd=='verify-cloudflare':
            return 0 if verify_cloudflare(args.domain) else 3
        valid_domain(args.domain)
        valid_public_ip(args.ip)
        return 0
    except (ValueError, KeyboardInterrupt, EOFError) as exc:
        print(f'Invalid install configuration: {exc}', file=sys.stderr)
        return 2

if __name__=='__main__':
    raise SystemExit(main())
