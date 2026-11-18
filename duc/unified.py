"""One shared authenticated server-side Dante, no client gateway.

A supported TCP tunnel forwards bytes to the *actual* SOCKS5 server, whose
RFC 1929 username/password challenge traverses the tunnel unchanged. A client
on port 2080 is simply a local TCP listener provided by its tunnel binary.
"""
from __future__ import annotations
import json
from . import core, dante

# NoizDNS server is now a separate build of the audited anonvector/dnstt fork.
# DNS2TCP remains excluded because it sends unencrypted application data.
TCP_ENGINES = ('slipstream', 'dnstt', 'vaydns', 'noizdns')
OTHER = ('dns2tcp', 'master', 'soar', 'iodine', 'xdns')
TARGET = dante.SOCKS_TARGET
BACKUP = core.ROOT / 'shared-backend-previous.json'

MODES = {
    'slipstream': ('shared-dante', 'custom-loopback'),
    'dnstt': ('shared-dante', 'custom-loopback'),
    'vaydns': ('shared-dante', 'custom-loopback'),
    'noizdns': ('shared-dante', 'custom-loopback'),
    'dns2tcp': ('plaintext-requires-ssh-wrapper',),
    'master': ('native-client-socks',),
    'soar': ('shared-dante-restricted',),
    'iodine': ('ip-tunnel',),
    'xdns': ('requires-matching-xray-config',),
}


def status():
    ds = dante.status()
    profiles = core.profiles()
    active = core.list_active()
    engines = {}
    for e in core.ENGINES:
        current = profiles[e].get('target')
        supported = e in TCP_ENGINES or e == 'soar'
        engines[e] = {
            'target': current,
            'mode': ('shared-dante-restricted' if e=='soar' else
                     ('shared-dante' if current==TARGET else 'custom-loopback'))
                    if supported else MODES[e][0],
            'shared_supported': supported,
            'client_local_port': 2080 if supported else
                                 profiles[e].get('client_port') if e=='master' else None,
            'client_listener_is_tunnel_binary': supported,
            'notes': {'noizdns':'Server uses anonvector/dnstt. NoizDNS/SlipNet sayedns Stealth tested with recursive DNS 1.1.1.1, HTTPS 200 and correct/incorrect local SOCKS credentials on 2026-11-07. Dante logs not independently correlated.',
                      'dns2tcp':'Plaintext DNS encapsulation can expose SOCKS credentials.',
                      'master':'Native SOCKS is not a raw TCP backend; Dante cannot be forced without audited upstream support.',
                      'soar':'Restricted Soar binary only accepts authenticated Dante at 127.0.0.1:1080.',
                      'iodine':'IP/TUN, not raw TCP.',
                      'xdns':'Requires tested matching Xray server/client configuration.'}.get(e,'')
        }
    return {
        'version':'0.9.8',
        'backend':{'installed':ds['installed'],'running':ds['running'],
                   'ready':ds['ready'],'bind':TARGET,'authentication':'username'},
        'client':{'bind':'127.0.0.1:2080','type':'Native local SOCKS5 or raw TCP to shared Dante, depending on tunnel engine',
                  'authentication':'server-side-Dante-RFC1929',
                  'gateway_required':False, 'automatic_client_switch':False,
                  'note':'Stop previous tunnel client and start selected client on port 2080.'},
        'engines':engines,'active_dns':active,'exclusive_healthy':len(active)<=1,
        'credentials_in_api':False,
    }


def configure(mode, names, target=None):
    """Change the *server* raw-TCP backend, never bind extra ports on client.

    Protect concurrent edits, back up original targets, and rollback if the
    panel-controlled restart fails. Custom ports remain loopback only.
    """
    if mode not in ('dante','custom','restore'):
        raise ValueError('mode must be dante, custom or restore')
    if not isinstance(names,list) or not names or len(set(names))!=len(names) or any(x not in TCP_ENGINES for x in names):
        raise ValueError('only unique audited TCP forwarders are allowed: '+', '.join(TCP_ENGINES))
    if mode=='custom':
        if len(names)!=1: raise ValueError('custom target changes exactly one engine')
        if not isinstance(target,str): raise ValueError('custom target is required')
        core.validate('target',target)
        if target==TARGET: mode='dante'
    elif target is not None: raise ValueError('target is valid for custom mode only')
    if mode=='dante' and not dante.status()['ready']:
        raise ValueError('The shared authenticated Dante service is not ready')
    existing=core.profiles()
    active=core.list_active()
    if len(active)>1: raise ValueError('Exclusive Mode conflict: multiple DNS engines are running')
    original=json.loads(BACKUP.read_text()) if BACKUP.exists() else {}
    if not isinstance(original,dict): raise ValueError('Original backend backup is corrupted')
    updated=core.profiles(); saved=dict(original); changed=[]
    for e in names:
        current=existing[e]['target']
        if mode=='restore':
            if e not in saved: raise ValueError(e+': no saved original target available')
            desired=saved[e]
        else:
            desired=TARGET if mode=='dante' else target
            if current!=TARGET and e not in saved: saved[e]=current
        core.validate('target',desired)
        if current==desired: continue
        updated[e]['target']=desired; changed.append(e)
    if not changed:
        return {'ok':True,'stage':'unchanged','engines':names,'active_dns':active}
    # Current runtime may be in /etc/dns-unified as current installation.
    with core.switch_lock():
        if core.list_active()!=active or core.profiles()!=existing:
            raise RuntimeError('Engine or profile changed during update; retry')
        if mode!='restore': core.atomic_json(BACKUP,saved)
        core.atomic_json(core.ROOT/'profiles.json',updated)
    restarted=active[0] if active and active[0] in changed else None
    if restarted:
        result=core.switch(restarted,restart=True)
        if not result.get('ok'):
            with core.switch_lock(): core.atomic_json(core.ROOT/'profiles.json',existing)
            rollback=core.switch(restarted,restart=True)
            raise RuntimeError('Restart failed; profile restored; rollback service '+
                               ('healthy' if rollback.get('ok') else 'requires manual inspection'))
    return {'ok':True,'stage':'updated','changed':changed,'restarted':restarted,
            'active_dns':core.list_active(),'client_gateway_required':False}


def main():
    import argparse
    parser=argparse.ArgumentParser(description='Shared Dante / no client-side gateway')
    parser.add_argument('action',choices=['status','attach','custom','restore','link'])
    parser.add_argument('engine',nargs='*')
    parser.add_argument('--target',default=None)
    a=parser.parse_args()
    if a.action=='status': result=status()
    elif a.action=='link':
        from .dante import credentials
        print(credentials().replace('#SlipStream-Dante','#DUC-Unified'))
        return
    else:
        names=a.engine or (['slipstream','dnstt','vaydns','noizdns'] if a.action!='custom' else [])
        result=configure({'attach':'dante','custom':'custom','restore':'restore'}[a.action],names,a.target)
    print(json.dumps(result,ensure_ascii=False,indent=2))

if __name__=='__main__':main()
