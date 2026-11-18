#!/usr/bin/env python3
"""Guarded one-record DNS-only Cloudflare A migration, including rollback.

By default READ-ONLY. Does not touch NS delegations, other A records or client keys.
"""
import argparse
import datetime
import getpass
import ipaddress
import json
import os
from pathlib import Path
import sys
import re
import urllib.error
import urllib.parse
import urllib.request

API = 'https://api.cloudflare.com/client/v4'
# Domain supplied explicitly per installation; never hardcode a customer zone.
MARKER = 'managed-by:dns-unified-control'

class GuardError(Exception): pass

# Avoid importing the installed privileged Agent from a standalone operator
# script; keep the accepted syntax consistent with the product preflight.
def valid_domain(value):
    value=value.strip().lower().rstrip('.')
    labels=value.split('.')
    if len(labels)<2 or len(value)>253 or not re.fullmatch(r'[a-z]{2,63}',labels[-1]) or not all(
        re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', x) for x in labels):
        raise GuardError('Invalid Cloudflare zone domain')
    return value

def ip(value):
    x=ipaddress.ip_address(value)
    if x.version!=4 or not x.is_global: raise GuardError('IPv4 must be public and routable')
    return str(x)

class Client:
    def __init__(self,token): self.token=token
    def call(self,method,path,body=None):
        data=json.dumps(body).encode() if body is not None else None
        headers={'Authorization':'Bearer '+self.token,'Accept':'application/json'}
        if body is not None: headers['Content-Type']='application/json'
        req=urllib.request.Request(API+path,headers=headers,data=data,method=method)
        try:
            with urllib.request.urlopen(req,timeout=22) as resp: obj=json.load(resp)
        except urllib.error.HTTPError as e:
            raise GuardError(f'Cloudflare HTTP {e.code}; inspect provider dashboard') from None
        except (urllib.error.URLError,TimeoutError):
            raise GuardError('Cloudflare connection error/timeout') from None
        if not obj.get('success'): raise GuardError('Cloudflare API rejected request')
        return obj.get('result')

def get_record(client,zone_id,fqdn):
    path='/zones/'+zone_id+'/dns_records?'+urllib.parse.urlencode({'name':fqdn,'per_page':100})
    rows=client.call('GET',path)
    exact=[r for r in rows if str(r.get('name','')).rstrip('.').lower()==fqdn]
    if len(exact)!=1 or exact[0].get('type')!='A':
        raise GuardError(f'Expected exactly one A record for {fqdn}, found {len(exact)} exact records')
    r=exact[0]
    if r.get('proxied') is not False: raise GuardError('DNS record must be DNS-only, not proxied')
    if MARKER not in (r.get('comment') or ''):
        raise GuardError('Record is not DUC-managed. Inspect/edit manually instead of forcing.')
    if not r.get('id'): raise GuardError('Record missing ID')
    return r

def write_audit(path,data):
    folder=Path(path).expanduser().resolve()
    folder.mkdir(mode=0o700,parents=True,exist_ok=True)
    stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    file=folder/f'dns-{data["label"]}-{stamp}.json'
    fd=os.open(file,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as out: json.dump(data,out,indent=2)
    return file

def main():
    p=argparse.ArgumentParser(description='Safe Cloudflare panel/ns A cutover or rollback (default dry-run)')
    p.add_argument('--label',choices=('panel','ns'),required=True)
    p.add_argument('--domain',required=True,help='Existing Cloudflare zone (e.g. example.org)')
    p.add_argument('--from-ip',required=True)
    p.add_argument('--to-ip',required=True)
    p.add_argument('--apply',action='store_true')
    p.add_argument('--audit-dir',default='./duc-dns-audit')
    a=p.parse_args()
    try:
        source,target=ip(a.from_ip),ip(a.to_ip)
        if source==target: raise GuardError('Old and new IP must differ')
        domain=valid_domain(a.domain)
        fqdn=a.label+'.'+domain
        token=getpass.getpass('Cloudflare API token (hidden, never stored): ').strip()
        if not token: raise GuardError('Missing token')
        client=Client(token)
        zones=client.call('GET','/zones?'+urllib.parse.urlencode({'name':domain,'per_page':50}))
        match=[z for z in zones if z.get('name')==domain and z.get('status')=='active']
        if len(match)!=1: raise GuardError('Active Cloudflare zone not accessible')
        zone=match[0]['id']
        r=get_record(client,zone,fqdn)
        if r.get('content')!=source:
            raise GuardError(f'{fqdn} current IP differs from expected old IP; not modifying anything')
        print(f'{"APPLY" if a.apply else "DRY-RUN"}: {fqdn} A {source} -> {target}')
        print('NS delegations and all other records are untouched.')
        if not a.apply: return 0
        print(f'CRITICAL: this immediately changes {fqdn} from {source} to {target}.')
        print('Keep the previous VPS online until traffic and DNS caches have converged.')
        if input('Apply this one-record Cloudflare DNS cutover? [yes/no] (default: no): ').strip().lower() != 'yes':
            raise GuardError('No explicit yes confirmation; no update')
        # Snapshot BEFORE remote mutation. No API tokens in audit files.
        audit={'label':a.label,'fqdn':fqdn,'from_ip':source,'to_ip':target,
               'record_id':r['id'],'zone_id':zone,'original_record':r,'status':'before-update'}
        audit_path=write_audit(a.audit_dir,audit)
        print(f'Local audit snapshot: {audit_path}')
        client.call('PATCH',f'/zones/{zone}/dns_records/{r["id"]}',{'content':target})
        updated=get_record(client,zone,fqdn)
        if updated.get('content')!=target: raise GuardError('Cloudflare verification failed; inspect dashboard immediately')
        print('VERIFIED: Cloudflare authoritative record changed. Recursive caches may still point to old IP.')
        print(f'ROLLBACK: python3 03-cloudflare-switch.py --domain {domain} --label {a.label} --from-ip {target} --to-ip {source} --apply')
        return 0
    except (GuardError,ValueError,EOFError,KeyboardInterrupt) as exc:
        print('ABORTED: '+str(exc or 'Interrupted'),file=sys.stderr)
        return 1

if __name__=='__main__':sys.exit(main())
