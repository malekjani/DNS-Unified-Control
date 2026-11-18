"""DUC-managed localhost-only authenticated Dante backend for SlipStream.

Dante is NOT a DNS engine. No public SOCKS socket, NAT, port 53 changes,
upstream deploy script, or alternate SlipStream service are ever created.
"""
from __future__ import annotations

import base64
import json
import os
import pathlib
import re
import secrets
import shutil
import socket
import subprocess
import time
from . import core

SOCKS_TARGET = '127.0.0.1:1080'
UNIT = 'dns-unified-dante.service'
AUTH_USER = 'duc-socks'
AUTH_FILE = core.ROOT/'keys/dante-auth.json'
CONF_FILE = core.ROOT/'danted.conf'
UNIT_FILE = pathlib.Path('/etc/systemd/system')/UNIT


def call(argv, *, input=None, timeout=60, ok=True):
    p=subprocess.run(argv, input=input, capture_output=True, text=True, timeout=timeout)
    if ok and p.returncode:
        raise RuntimeError(f'{argv[0]} exited {p.returncode}: {(p.stderr or p.stdout)[-500:]}')
    return p


def iface():
    """Choose outbound IPv4 interface; do not infer from client-facing SOCKS NIC."""
    p=call(['ip','-4','route','get','1.1.1.1'],timeout=6)
    match=re.search(r'\bdev\s+([a-zA-Z0-9_.-]+)',p.stdout)
    if not match: raise RuntimeError('No IPv4 egress interface found')
    return match.group(1)


def configuration(interface):
    if not re.fullmatch(r'[a-zA-Z0-9_.-]{1,32}',interface):
        raise ValueError('Unexpected interface name')
    return f'''# DNS Unified Control: Dante backend, private on loopback only.
# All clients must authenticate using system account {AUTH_USER}.
logoutput: syslog
internal: 127.0.0.1 port = 1080
external: {interface}
user.privileged: root
user.unprivileged: nobody
clientmethod: none
socksmethod: username

client pass {{
  from: 127.0.0.1/32 to: 0.0.0.0/0
  log: error
}}

# Deny access to IPv4 local/private/metadata destinations even after authentication.
socks block {{ from: 0.0.0.0/0 to: 0.0.0.0/8 }}
socks block {{ from: 0.0.0.0/0 to: 10.0.0.0/8 }}
socks block {{ from: 0.0.0.0/0 to: 100.64.0.0/10 }}
socks block {{ from: 0.0.0.0/0 to: 127.0.0.0/8 }}
socks block {{ from: 0.0.0.0/0 to: 169.254.0.0/16 }}
socks block {{ from: 0.0.0.0/0 to: 172.16.0.0/12 }}
socks block {{ from: 0.0.0.0/0 to: 192.168.0.0/16 }}
socks block {{ from: 0.0.0.0/0 to: 224.0.0.0/4 }}
socks pass {{
  from: 0.0.0.0/0 to: 0.0.0.0/0
  command: connect
  protocol: tcp
  socksmethod: username
  log: error
}}
'''


SYSTEMD = '''[Unit]
Description=DNS Unified Dante SOCKS5 backend (loopback only)
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
ExecStart=/usr/sbin/danted -f /etc/dns-unified/danted.conf
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=full
[Install]
WantedBy=multi-user.target
'''


def auth_record():
    if not AUTH_FILE.is_file():
        raise RuntimeError('SOCKS credentials are missing; run Dante setup')
    data=json.loads(AUTH_FILE.read_text())
    if data.get('user')!=AUTH_USER or not 16 <= len(data.get('password',''))<=150:
        raise RuntimeError('Invalid SOCKS credentials')
    if AUTH_FILE.stat().st_mode & 0o077:
        raise RuntimeError('SOCKS credential file permissions are unsafe')
    return data


def authenticated_greeting():
    try:
        data=auth_record()
        user=data['user'].encode('utf-8'); password=data['password'].encode('utf-8')
        with socket.create_connection(('127.0.0.1',1080),timeout=3) as sock:
            sock.settimeout(3)
            def recvn(n):
                result=b''
                while len(result)<n:
                    part=sock.recv(n-len(result))
                    if not part:return result
                    result+=part
                return result
            sock.sendall(b'\x05\x01\x02')
            if recvn(2)!=b'\x05\x02': return False
            sock.sendall(b'\x01'+bytes([len(user)])+user+bytes([len(password)])+password)
            return recvn(2)==b'\x01\x00'
    except (OSError,RuntimeError,ValueError):return False


def status():
    cp=call(['systemctl','is-active','--quiet',UNIT],timeout=5,ok=False)
    active=cp.returncode==0
    installed=shutil.which('danted') is not None or pathlib.Path('/usr/sbin/danted').exists()
    try:profile=core.profiles()['slipstream']['target']
    except (OSError,ValueError,KeyError):profile='unknown'
    verified=authenticated_greeting() if active else False
    return {'installed':installed,'running':active,'auth_verified':verified,
            'ready':active and verified,'bind':SOCKS_TARGET,
            'auth_enabled':AUTH_FILE.is_file(),
            'profile_target':profile,'profile_mode':'SOCKS5' if profile==SOCKS_TARGET else 'SSH' if profile=='127.0.0.1:22' else 'custom',
            'active_dns':core.list_active(), 'unit':UNIT,
            'note':'Credential material is not returned by API; available to root only via CLI.'}


def install():
    if os.geteuid():raise RuntimeError('Root is required to install Dante')
    if call(['systemctl','is-active','--quiet','danted.service'],timeout=5,ok=False).returncode==0:
        raise RuntimeError('An independently managed danted.service is already active; refusing to replace it.')
    if call(['systemctl','is-active','--quiet',UNIT],timeout=5,ok=False).returncode!=0:
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
            try:s.bind(('127.0.0.1',1080))
            except OSError:raise RuntimeError('Local TCP 1080 is already occupied; no changes made')
    if not pathlib.Path('/usr/sbin/danted').is_file():
        env=dict(os.environ,DEBIAN_FRONTEND='noninteractive')
        # Apt may create the distro unit. Stop it only when it was not already active.
        call(['apt-get','update'],timeout=250)
        call(['apt-get','install','-y','dante-server'],timeout=400)
        call(['systemctl','disable','--now','danted.service'],timeout=20,ok=False)
    interface=iface()
    core.ROOT.mkdir(mode=0o750,parents=True,exist_ok=True)
    if AUTH_FILE.exists():
        credentials=auth_record()
    else:
        credentials={'user':AUTH_USER,'password':secrets.token_urlsafe(27)}
    if call(['id','-u',AUTH_USER],timeout=5,ok=False).returncode:
        call(['useradd','--system','--no-create-home','--shell','/usr/sbin/nologin',AUTH_USER],timeout=20)
    # Setting the account's password is required for Dante's 'username' method.
    call(['chpasswd'],input=AUTH_USER+':'+credentials['password']+'\n',timeout=20)
    if not AUTH_FILE.exists():core.atomic_json(AUTH_FILE,credentials)
    elif AUTH_FILE.stat().st_mode & 0o077:raise RuntimeError('Unsafe existing SOCKS password file')
    old=CONF_FILE.read_bytes() if CONF_FILE.is_file() else None
    try:
        conf=configuration(interface)
        tmp=CONF_FILE.with_name('danted.conf.pending')
        tmp.write_text(conf)
        tmp.chmod(0o600)
        call(['/usr/sbin/danted','-V','-f',str(tmp)],timeout=15)
        os.replace(tmp,CONF_FILE)
        CONF_FILE.chmod(0o600)
        UNIT_FILE.write_text(SYSTEMD)
        UNIT_FILE.chmod(0o644)
        call(['systemctl','daemon-reload'],timeout=20)
        if call(['systemctl','is-active','--quiet',UNIT],timeout=5,ok=False).returncode==0:
            call(['systemctl','restart',UNIT],timeout=25)
        else:
            call(['systemctl','enable','--now',UNIT],timeout=35)
        for _ in range(20):
            if authenticated_greeting():break
            time.sleep(0.25)
        else:
            raise RuntimeError('Dante did not accept authenticated SOCKS5 locally. Check journalctl -u '+UNIT)
    except Exception:
        if old is not None:
            CONF_FILE.write_bytes(old);CONF_FILE.chmod(0o600)
        elif CONF_FILE.exists():CONF_FILE.unlink()
        raise
    return {'message':'Authenticated Dante SOCKS5 ready at 127.0.0.1:1080; SlipStream was NOT restarted, and UDP/53 was NOT touched.'}


def activate(mode):
    if mode not in ('socks5','ssh'):raise ValueError('Only socks5 and ssh backend modes are supported')
    target=SOCKS_TARGET if mode=='socks5' else '127.0.0.1:22'
    if mode=='socks5' and not status()['ready']:
        raise ValueError('Dante is not healthy. Install/verify Dante first.')
    old=core.profiles()['slipstream']['target']
    active=core.list_active()
    if len(active)>1:raise ValueError('Multiple DNS engines are running; repair Exclusive Mode first')
    if old==target:return {'ok':True,'stage':'already-configured','target':target,'active_dns':active}
    core.update_profile('slipstream',{'target':target})
    if active==['slipstream']:
        result=core.switch('slipstream',restart=True)
        if not result.get('ok'):
            core.update_profile('slipstream',{'target':old})
            core.switch('slipstream',restart=True)
            raise RuntimeError('SlipStream restart failed; previous profile restored. Check systemd journal.')
        return {'ok':True,'stage':'slipstream-restarted','target':target,'active_dns':core.list_active()}
    return {'ok':True,'stage':'saved-for-next-slipstream-start','target':target,'active_dns':active}


def credentials():
    data=auth_record()
    token=base64.b64encode(f"{data['user']}:{data['password']}".encode()).decode()
    return f"socks://{token}@127.0.0.1:2080#SlipStream-Dante"


def main():
    import sys
    if os.geteuid():raise SystemExit('Run as root')
    if len(sys.argv)!=2 or sys.argv[1] not in ('install','status','activate','ssh','credentials'):
        raise SystemExit('Usage: python -m duc.dante {install|status|activate|ssh|credentials}')
    action=sys.argv[1]
    if action=='install':print(json.dumps(install(),ensure_ascii=False))
    elif action=='status':print(json.dumps(status(),indent=2))
    elif action=='activate':print(json.dumps(activate('socks5')))
    elif action=='ssh':print(json.dumps(activate('ssh')))
    elif action=='credentials':print(credentials())

if __name__=='__main__':main()
