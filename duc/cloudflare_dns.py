"""One-shot Cloudflare DNS delegation provisioner. Tokens are never persisted."""
from __future__ import annotations
from .confirm import ask_yes_no
import argparse
import getpass
import ipaddress
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

API = 'https://api.cloudflare.com/client/v4'
MARKER = 'managed-by:dns-unified-control'
LABEL = re.compile(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$')

class ProvisionError(Exception):
    pass

def clean_domain(value):
    value = value.strip().lower().rstrip('.')
    labels = value.split('.')
    if len(labels) < 2 or len(value) > 253 or not all(LABEL.fullmatch(x) for x in labels):
        raise ProvisionError('Invalid domain name')
    return value

def clean_label(value):
    value = value.strip().lower()
    if not LABEL.fullmatch(value):
        raise ProvisionError('Invalid DNS label')
    return value

def clean_ip(value):
    try:
        ip = ipaddress.ip_address(value.strip())
        if not isinstance(ip, ipaddress.IPv4Address) or not ip.is_global:
            raise ValueError()
        return str(ip)
    except ValueError as e:
        raise ProvisionError('A public IPv4 address is required') from e

@dataclass
class CF:
    token: str
    base: str = API

    def call(self, method, path, data=None):
        url = self.base + path
        headers = {'Authorization': 'Bearer ' + self.token, 'Accept': 'application/json'}
        payload = None
        if data is not None:
            payload = json.dumps(data).encode('utf-8')
            headers['Content-Type'] = 'application/json'
        request = urllib.request.Request(url, data=payload, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=20) as resp:
                answer = json.loads(resp.read(2_000_000))
        except urllib.error.HTTPError as e:
            # Cloudflare may return verbose diagnostics; never echo request headers or token.
            try:
                body = json.loads(e.read(20000))
                codes = ', '.join(str(x.get('code','?')) for x in body.get('errors', []))
            except (ValueError, KeyError):
                codes = 'unknown'
            raise ProvisionError(f'Cloudflare API HTTP {e.code}, error code(s): {codes}') from None
        except (urllib.error.URLError, TimeoutError) as e:
            raise ProvisionError('Cloudflare API request failed (network/timeout)') from e
        if not answer.get('success'):
            codes = ', '.join(str(x.get('code','?')) for x in answer.get('errors', []))
            raise ProvisionError('Cloudflare API returned unsuccessful response: '+codes)
        return answer.get('result')

    def zone(self, domain):
        query = urllib.parse.urlencode({'name':domain, 'per_page':50})
        zones = self.call('GET', '/zones?'+query)
        match = [z for z in zones if z.get('name') == domain]
        if len(match) != 1:
            raise ProvisionError('Domain zone not available to this token; add the domain to Cloudflare and authorize Zone Read')
        if match[0].get('status') != 'active':
            raise ProvisionError('Cloudflare zone is not active yet; update registrar nameservers first')
        return match[0]['id']

    def records(self, zone, name):
        q = urllib.parse.urlencode({'name':name, 'per_page':100})
        return self.call('GET',f'/zones/{zone}/dns_records?{q}')

def record_plan(domain, ipv4, host='ns', tunnel='v'):
    domain = clean_domain(domain); ipv4 = clean_ip(ipv4)
    host, tunnel = clean_label(host), clean_label(tunnel)
    if host == tunnel: raise ProvisionError('Nameserver and tunnel labels must be different')
    ns = f'{host}.{domain}'
    delegate = f'{tunnel}.{domain}'
    return [
        {'type':'A','name':ns,'content':ipv4,'ttl':120,'proxied':False,'comment':MARKER},
        {'type':'NS','name':delegate,'content':ns,'ttl':120,'comment':MARKER},
    ]

def decide(existing, wanted):
    # Protect user's records, including same-name A/CNAME, multiple NS targets, and proxy settings.
    if not existing: return 'create', None
    same_type = [r for r in existing if r.get('type') == wanted['type']]
    other = [r for r in existing if r.get('type') != wanted['type']]
    if other or len(same_type) != 1 or len(existing) != 1:
        raise ProvisionError(f'Conflicting records exist at {wanted["name"]}; change them manually')
    old = same_type[0]
    if old.get('content','').rstrip('.').lower() == wanted['content'].rstrip('.').lower() and (wanted['type'] != 'A' or old.get('proxied') is False):
        return 'unchanged',old.get('id')
    if MARKER not in (old.get('comment') or ''):
        raise ProvisionError(f'Unmanaged record at {wanted["name"]}; refusing to overwrite')
    if not old.get('id'):
        raise ProvisionError('Record missing ID')
    return 'update', old['id']

def apply(client, domain, ipv4, host='ns', tunnel='v', dry_run=False):
    plan = record_plan(domain, ipv4, host, tunnel)
    zone = client.zone(clean_domain(domain))
    operations = []
    # Read/validate both records first, before writing either.
    for rec in plan:
        action, ident = decide(client.records(zone, rec['name']), rec)
        operations.append((action, ident, rec))
    if not dry_run:
        for action, ident, rec in operations:
            if action == 'create':
                client.call('POST', f'/zones/{zone}/dns_records', rec)
            elif action == 'update':
                client.call('PATCH', f'/zones/{zone}/dns_records/{ident}', rec)
    return [{'action':a, 'type':r['type'], 'name':r['name'], 'content':r['content']} for a,_,r in operations]


def record_plan_all(domain, ipv4, host='ns'):
    """One A glue target plus one NS delegation per engine (never a shared zone)."""
    from .catalog import ENGINES, LABELS
    domain, ipv4, host = clean_domain(domain), clean_ip(ipv4), clean_label(host)
    if host in LABELS.values():
        raise ProvisionError('Nameserver label collides with an engine delegation')
    ns=f'{host}.{domain}'
    records=[{'type':'A','name':ns,'content':ipv4,'ttl':120,'proxied':False,'comment':MARKER}]
    for engine in ENGINES:
        records.append({'type':'NS','name':f'{LABELS[engine]}.{domain}',
                        'content':ns,'ttl':120,'comment':MARKER})
    return records

def apply_all(client, domain, ipv4, host='ns',dry_run=False):
    """Preflight every DNS record before writing any records. Partial remote writes remain possible."""
    plan=record_plan_all(domain,ipv4,host)
    zone=client.zone(clean_domain(domain))
    operations=[]
    for rec in plan:
        action, ident=decide(client.records(zone,rec['name']),rec)
        operations.append((action, ident, rec))
    if not dry_run:
        for action,ident,rec in operations:
            if action=='create':client.call('POST',f'/zones/{zone}/dns_records',rec)
            elif action=='update':client.call('PATCH',f'/zones/{zone}/dns_records/{ident}',rec)
    return [{'action':a,'type':r['type'],'name':r['name'],'content':r['content']} for a,_,r in operations]

def public_ip():
    req = urllib.request.Request('https://api.ipify.org', headers={'User-Agent':'dns-unified-control/0.4'})
    try:
        with urllib.request.urlopen(req, timeout=8) as response:
            return clean_ip(response.read(80).decode())
    except (urllib.error.URLError, ValueError, ProvisionError):
        raise ProvisionError('Cannot detect public IPv4; supply --ip') from None

def main(argv=None):
    parser = argparse.ArgumentParser(description='Provision Cloudflare delegation for exclusive DNS tunnels')
    parser.add_argument('--domain',help='Cloudflare active zone (e.g. akr.cfd)')
    parser.add_argument('--ip',help='Public IPv4 of VPS; autodetected if omitted')
    parser.add_argument('--ns-label',default='ns')
    parser.add_argument('--tunnel-label',default='v',help='Legacy single-domain mode only')
    parser.add_argument('--single',action='store_true',help='Legacy mode: one shared delegation, not recommended')
    parser.add_argument('--dry-run',action='store_true')
    parser.add_argument('--no-profile-update',action='store_true')
    args = parser.parse_args(argv)
    try:
        domain = clean_domain(args.domain or input('Cloudflare domain: '))
        ipv4 = clean_ip(args.ip) if args.ip else public_ip()
        token = getpass.getpass('Cloudflare API Token (hidden, not saved): ').strip()
        if not token: raise ProvisionError('API token is required')
        plan = record_plan(domain, ipv4, args.ns_label, args.tunnel_label) if args.single else record_plan_all(domain,ipv4,args.ns_label)
        print('\nProposed DNS records:')
        for r in plan: print(f'  {r["type"]:2}  {r["name"]} -> {r["content"]}')
        print('  A record: DNS only / not proxied')
        if not args.dry_run:
            if not ask_yes_no('Apply proposed DNS record changes to Cloudflare?'):
                print('Cancelled; no changes made')
                return 0
        result = (apply(CF(token),domain,ipv4,args.ns_label,args.tunnel_label,args.dry_run)
                  if args.single else apply_all(CF(token),domain,ipv4,args.ns_label,args.dry_run))
        for row in result:print(f'{"WOULD " if args.dry_run else ""}{row["action"].upper()}: {row["type"]} {row["name"]}')
        if not args.dry_run and not args.no_profile_update:
            from .core import ENGINES, ROOT, profiles, atomic_json
            data = profiles()
            from .catalog import LABELS
            for name in ENGINES:
                data[name]['domain'] = (plan[1]['name'] if args.single else f'{LABELS[name]}.{domain}')
            atomic_json(ROOT/'profiles.json',data)
            print('Updated per-engine domain profiles:', ', '.join(v['domain'] for v in data.values()))
        print('DNS propagation and authoritative tunnel endpoint need separate validation.')
        return 0
    except (ProvisionError, EOFError, KeyboardInterrupt) as e:
        print('Cloudflare setup error: ' + (str(e) if str(e) else 'interrupted'),file=sys.stderr)
        return 1

if __name__ == '__main__':
    raise SystemExit(main())
