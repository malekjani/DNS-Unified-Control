"""Audited operational guidance. Read-only: never exposes private keys or CF tokens."""
from __future__ import annotations
import hashlib
import ipaddress
import os
import pathlib
import re
import shlex
import shutil
import subprocess
from . import core
from .catalog import ENGINES, LABELS, NAMES

CLIENT_CAPABILITIES = {
 'master': ('build', 'Build matching MasterDnsVPN client + SOCKS5 config. Client ZIP contains a SHARED ENCRYPTION SECRET; keep it private.'),
 'slipstream': ('pack-if-installed', 'Rust Linux amd64 client; pinned certificate must accompany the executable.'),
 'dnstt': ('build', 'Build a Linux amd64 client from the same upstream source as the server, package public key.'),
 'noizdns': ('native-slipnet-verified-release', 'Official SlipNet Go CLI uses sayedns + stealth=true. Recursive DNS SOCKS5 HTTPS and local auth accepted/rejected in field test; remote Dante log correlation remains separate.'),
 'vaydns': ('build', 'Build matching VayDNS client with public key and tested CLI syntax.'),
 'soar': ('build', 'Restricted Soar server dials only authenticated shared Dante; native Go-powered client ZIP contains no passwords.'),
 'iodine': ('distro', 'IP-over-DNS needs the iodine client and routing setup; traffic is not encrypted.'),
 'dns2tcp': ('distro', 'TCP-over-DNS needs dns2tcpc; traffic is not encrypted.'),
 'xdns': ('manual', 'XDNS is an Xray FinalMask feature, not an independent generic client.'),
}

DOCS = {
 'master':'https://github.com/masterking32/MasterDnsVPN',
 'slipstream':'https://github.com/AliRezaBeigy/slipstream-rust-deploy/releases/tag/42e3e75',
 'dnstt':'https://github.com/net2share/dnstt',
 'noizdns':'https://github.com/anonvector/SlipNet',
 'vaydns':'https://github.com/net2share/dnstm/blob/main/docs/CLIENT.md',
 'soar':'https://github.com/getlantern/soar',
 'iodine':'https://code.kryo.se/iodine/',
 'dns2tcp':'https://github.com/alex-sector/dns2tcp',
 'xdns':'https://github.com/XTLS/Xray-core',
}


def shell(args):
    return shlex.join([str(x) for x in args])


def public_key(engine):
    if engine not in ('dnstt','noizdns','vaydns'): return None
    path = core.ROOT/'keys'/f'{engine}.pub'
    try:
        value = path.read_text(encoding='ascii').strip().lower()
        return value if re.fullmatch(r'[0-9a-f]{64}',value) else None
    except (OSError, UnicodeError): return None


def build_client_guide(engine, resolver='1.1.1.1:53', local_port=2080):
    if engine not in ENGINES: raise ValueError('unknown engine')
    if type(local_port) is not int or not 1024 <= local_port <= 65535:
        raise ValueError('local_port must be 1024..65535')
    if not isinstance(resolver,str) or not re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}:\d{1,5}',resolver):
        raise ValueError('resolver must be an IPv4:port endpoint')
    host,port=resolver.rsplit(':',1)
    try: ipaddress.IPv4Address(host)
    except ValueError: raise ValueError('invalid resolver IP')
    if not 1<=int(port)<=65535: raise ValueError('invalid resolver port')
    c=core.profiles()[engine]
    domain=c['domain']
    mode,note=CLIENT_CAPABILITIES[engine]
    steps=[]
    command=None
    verification=None
    if engine=='dnstt':
        key=public_key('dnstt')
        if key:
            command=shell(['./dnstt-client','-udp',resolver,'-pubkey-file','./server.pub',domain,f'127.0.0.1:{local_port}'])
        else:steps.append('Generate server keypair first; public key is unavailable (never copy private key).')
        verification=('curl --socks5-hostname 127.0.0.1:'+str(local_port)+' --proxy-user USER:PASS https://api.ipify.org' if c.get('target')=='127.0.0.1:1080' else shell(['ssh-keyscan','-T','35','-p',str(local_port),'127.0.0.1']))
        steps += [
            'Start the downloaded client on your Linux computer (not on the VPS). Keep the process open.',
            'Use the SOCKS5 HTTPS probe for Dante. For SSH targets, use a real authenticated SSH client (ssh-keyscan can be misleading).',
            'For recursive DNS testing use 1.1.1.1:53 or 8.8.8.8:53. Direct VPS_IP:53 tests reachability, not recursive delegation.',
            'If backend is shared Dante, the local forward speaks authenticated SOCKS5; otherwise it is raw TCP.',
            'For shared Dante the local TCP forward already speaks authenticated SOCKS5; no SSH proxy or Gateway is needed.',
        ]
    elif engine=='slipstream':
        # Follow profile while preserving the UI-selected primary resolver.
        args=['./slipstream-rust-client','--domain',domain,
              '--tcp-listen-host','127.0.0.1','--tcp-listen-port',str(local_port),
              '--cert','./slipstream-rust.crt','--resolver',resolver]
        for addr in c.get('client_resolvers','').split(','):
            if addr and addr!=resolver:args.extend(['--resolver',addr])
        for addr in c.get('client_authoritative','').split(','):
            if addr and addr!=resolver:args.extend(['--authoritative',addr])
        cc=c.get('client_cc','auto')
        if cc!='auto':args.extend(['--congestion-control',cc])
        args.extend(['--keep-alive-interval',str(c.get('client_keep_alive',400))])
        command=shell(args)
        # This release delays server-first data on a new stream. Unlike
        # ssh-keyscan, OpenSSH sends its identification first and was verified
        # to complete KEX/NEWKEYS over a real recursive DNS path.
        if c.get('target')=='127.0.0.1:1080':
            verification='SOCKS5 requires Dante username/password: curl --socks5-hostname 127.0.0.1:'+str(local_port)+' --proxy-user USER:PASS https://api.ipify.org'
        elif c.get('target')=='127.0.0.1:22':
            verification=shell(['ssh','-vv','-o','BatchMode=yes',
                                '-o','PreferredAuthentications=none',
                                '-o','ConnectTimeout=30','-p',str(local_port),
                                'root@127.0.0.1'])
        else:
            verification='Backend-specific TCP test required: confirm that the configured localhost target is the intended SOCKS5 or Shadowsocks service.'
        steps += [
            'FA: بسته از انتشار پین‌شده AliRezaBeigy تهیه شده؛ مدیریت systemd، فایروال و UDP/53 فقط با پنل است.',
            'EN: Matched AliRezaBeigy binaries are managed exclusively by DNS Unified Control, NOT by the original deploy script.',
            'FA: گواهی عمومی برای pinning داخل ZIP است؛ فایل کلید خصوصی سرور هرگز دانلود نمی‌شود.',
            'EN: Pin the bundled TLS certificate; verify SOCKS credentials when Dante is backend.',
            'FA: --resolver مسیر DNS بازگشتی است؛ --authoritative اختیاری و نیازمند بررسی شبکه است.',
            'EN: --congestion-control accepts bbr or dcubic; auto leaves upstream default unchanged.',
            'EN: --keep-alive-interval is in milliseconds. --gso is not supported in the Rust loop; do not enable it.',
            f'FA: مقصد فعال این پروفایل {c.get("target")} است؛ پورت کلاینت raw TCP است، نه SOCKS5 خودکار.',
            'EN: The SlipStream local TCP forward is not SOCKS5 unless the server target itself speaks SOCKS5.',
            'EN: For SSH backend a real SSH client succeeds with client-first KEX even if ssh-keyscan times out; authentication requires a valid SSH account.',
            'FA: Dante با نصب از پنل فقط روی 127.0.0.1:1080 اجرا می‌شود و برای امنیت نیاز به نام کاربری/رمز دارد. مقصد SlipStream را از بخش Dante به SOCKS5 تغییر بده.',
            'EN: Dante is localhost-only and requires a username/password. Retrieve the v2rayN SOCKS URI on VPS as root using python -m duc.dante credentials. Never publish the URI.',
            'EN: For Shadowsocks (TCP-only), point server target to loopback ss-server:8388, then ss-local should connect to the SlipStream forwarded LOCAL TCP port, NOT a SlipStream-generated SOCKS proxy.',
            'EN: GUI and Android client support depends on matching the exact wire protocol/release; test compatibility first.',
            'FA: هنگام نصب، سرویس دیگری ساخته نمی‌شود؛ تغییر موتور فقط از کنترل Exclusive Mode پنل انجام می‌گیرد.',
        ]
    elif engine=='vaydns':
        key=public_key('vaydns')
        if key:
            cli=['./vaydns-client','-udp',resolver,'-pubkey-file','./server.pub',
                 '-domain',domain,'-listen',f'127.0.0.1:{local_port}']
            if c.get('dnstt_compat'):cli+=['-dnstt-compat']
            if c.get('vay_idle_timeout',10)!=10:cli+=['-idle-timeout',str(c['vay_idle_timeout'])+'s']
            if c.get('vay_keepalive',2)!=2:cli+=['-keepalive',str(c['vay_keepalive'])+'s']
            command=shell(cli)
        verification=('curl --socks5-hostname 127.0.0.1:'+str(local_port)+' --proxy-user USER:PASS https://api.ipify.org' if c.get('target')=='127.0.0.1:1080' else shell(['ssh-keyscan','-T','35','-p',str(local_port),'127.0.0.1']))
        steps += ['Run the matching client from the downloaded ZIP with its bundled server.pub.',
                  'With shared Dante selected, the VayDNS local TCP port directly carries authenticated SOCKS5.',
                  'Server and client record-type and compatibility flags must match.']
    elif engine=='iodine':
        command=shell(['iodine','-f',domain])
        steps += ['Install the iodine client on the Linux computer (apt install iodine).',
                  'Obtain the shared password by a separate secure channel; enter it at the client password prompt, never embed it in a ZIP or command line.',
                  'IP routing and NAT require explicit setup; iodine does not encrypt payloads.']
    elif engine=='dns2tcp':
        command=None
        steps += ['No safe universal command: inspect dns2tcpc help and the selected version; supply the configured resource and recursive resolver.',
                  'Provide the shared secret securely, never include it in generated client files.',
                  'dns2tcp is not encrypted; use SSH over the forwarded TCP port.']
    elif engine=='master':
        command=shell(['./masterdnsvpn-client','-config','./client_config.toml'])
        verification='curl -4 --max-time 60 --proxy socks5h://127.0.0.1:'+str(c.get('client_port',local_port))+' https://api.ipify.org'
        steps += ['Build client from the exact cached server source; Master requires matching config and encryption key.',
                  'The downloadable ZIP contains the SHARED SECRET in client_config.toml. Treat the ZIP as a password; never publish it.',
                  'The native Master SOCKS5 client port is configurable and defaults to 2080 in newly built packages; it is not Dante and may have separate auth support.',
                  'After switching to Master in Exclusive Mode, run the client; then use the SOCKS5 curl command.']
    elif engine=='noizdns':
        from . import slipnet_native
        key=public_key('noizdns')
        if key:
            command='./run-noizdns.sh  # official SlipNet CLI, native NoizDNS Stealth, no external gateway'
        else:steps.append('The NoizDNS public key is missing; server bootstrap must finish first.')
        verification='curl -4 -v --max-time 90 --socks5-hostname 127.0.0.1:'+str(local_port)+' --proxy-user USER:PASS https://api.ipify.org'
        steps += [
            'The installer auto-provisions the independent anonvector/dnstt server and matching public key.',
            'The client ZIP includes official SHA256-verified SlipNet CLI and a secret-free sayedns profile with NoizDNS Stealth enabled (field 38).',
            'Run run-noizdns.sh on Debian; it passes --dns 1.1.1.1:53 (or DUC_DNS_RESOLVER), to avoid accidental direct fallback. Native SlipNet only; no Gateway.',
            'Local SlipNet SOCKS credentials were positively/negatively tested. To prove Dante auth as verifier, correlate VPS Dante logs with the request.',
            'Avoid run-noizdns-inject-auth.sh unless troubleshooting specifically requires injection; it may expose encoded credentials in process arguments.',
            'NoizDNS Stealth/SlipNet with 1.1.1.1 recursive DNS, HTTPS 200, and positive/negative SOCKS5 credentials was field-tested on 2026-11-07. Remote Dante authentication logs were not independently inspected.',
        ]
    elif engine=='soar':
        from .soar_secure import public_key as soar_public_key
        key=soar_public_key()
        if key:
            command=shell(['./soar-client','-zone',domain,'-pubkey',key,
                           '-resolver',resolver,'-listen',f'127.0.0.1:{local_port}',
                           '-forward','127.0.0.1:1080'])
        else:steps.append('Install Soar server in web panel to generate the matching public key.')
        verification='curl -4 --socks5-hostname 127.0.0.1:'+str(local_port)+' --proxy-user USER:PASS https://api.ipify.org'
        steps += ['Install/prepare Soar and generate Ed25519 keys in the panel.',
                  'Build and download the Linux x86_64 native client ZIP from the panel.',
                  'Ensure Shared Dante is healthy; only then switch to Soar in Exclusive Mode.',
                  'Close the previous tunnel client and run the Soar client on local 2080.',
                  'Set v2rayN/FoxyProxy to SOCKS5 127.0.0.1:2080 with the EXISTING Dante username/password.',
                  'Server refuses all destinations other than 127.0.0.1:1080. This is NOT the upstream public-destination mode.']
    elif engine=='xdns':
        steps += ['Supply matching Xray FinalMask server/client JSON and validate both with xray run -test.',
                  'No independent XDNS binary or universal JSON template exists.']
    return {'engine':engine,'name':NAMES[engine],'domain':domain,'mode':mode,'note':note,
            'can_build':engine in ('dnstt','master','vaydns','slipstream','soar','noizdns'), 'example_command':command,
            'verification_command':verification,'steps':steps,'docs':DOCS[engine],
            'public_key':(soar_public_key() if engine=='soar' else public_key(engine))}


def snapshot():
    """Low-impact local inspection. The authoritative/recursive DNS check is separate."""
    def cmd(args,timeout=5):
        try:
            cp=subprocess.run(args,capture_output=True,text=True,timeout=timeout,check=False)
            return cp.stdout.strip() if cp.returncode==0 else ''
        except (OSError,subprocess.TimeoutExpired): return ''
    listeners=cmd(['ss','-H','-lntup'])
    def listening(port):
        return [line.split()[4] for line in listeners.splitlines() if len(line.split())>=5 and line.split()[4].rsplit(':',1)[-1]==str(port)]
    try:
        import psutil
        disk=psutil.disk_usage('/')
        ram=psutil.virtual_memory()
        swap=psutil.swap_memory()
        resources={'ram_available':ram.available,'ram_total':ram.total,'swap_total':swap.total,'swap_used':swap.used,
                   'disk_free':disk.free, 'cpu_count':psutil.cpu_count()}
    except ImportError:resources={}
    try:
        mfa=pathlib.Path('/var/lib/dns-unified/mfa/web-mfa.json').is_file()
    except OSError:mfa=False
    https=cmd(['systemctl','is-active','caddy'])=='active'
    web=cmd(['systemctl','is-active','dns-unified-web.service'])=='active'
    agent=cmd(['systemctl','is-active','dns-unified-agent.socket'])=='active'
    return {'resources':resources, 'services':{'web':web,'agent':agent,'caddy':https},
        'mfa_file_configured':mfa,'https_service_only':https,
        'port53':listening(53),'tcp80':listening(80),'tcp443':listening(443),
        'public_udp53_verified':False,'client_tunnel_verified':False,
        'dns_stub_listener':any('127.0.0.53' in a or '127.0.0.54' in a for a in listening(53)),
        'resolver_link':str(pathlib.Path('/etc/resolv.conf').resolve()),
        'notes':['HTTPS service/port checks are local; browser or validated HTTPS GET needed for external TLS.',
                 'A DNS delegation or running service does not confirm a real client-to-server tunnel.',
                 'Do not publish Cloudflare tokens or the TOTP secret. Rotate previously exposed credentials.']}


def create_public_guide_bundle(engine,resolver='1.1.1.1:53',local_port=2080):
    """Every method has a downloadable, honest guide; only verified builders include an ELF."""
    import io, zipfile, json
    guide=build_client_guide(engine,resolver,local_port)
    text=f"{guide['name']} | {guide['domain']}\nMode: {guide['mode']}\nNote: {guide['note']}\n\n"
    text+='Command (where validated):\n'+(guide['example_command'] or 'NOT VERIFIED FOR THIS UPSTREAM VERSION')+'\n\n'
    text+='Verification: '+(guide['verification_command'] or 'MANUAL')+'\n\n'
    text+='Steps:\n'+'\n'.join(f'{i}. {s}' for i,s in enumerate(guide['steps'],1))+'\n\n'
    text+='Upstream: '+guide['docs']+'\n'
    output=io.BytesIO()
    with zipfile.ZipFile(output,'w',compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr('README.txt',text)
        if engine=='noizdns':
            from . import slipnet_native
            if guide['public_key']:
                z.writestr('slipnet-profile.txt',slipnet_native.profile_text(guide['domain'],guide['public_key'],resolver,local_port)+'\n')
            z.writestr('UPSTREAM.txt','https://github.com/anonvector/SlipNet\nSlipNet Go CLI; sayedns+Stealth\n')
        else:
            z.writestr('client-profile.json',json.dumps({k:v for k,v in guide.items() if k not in ('public_key',)},indent=2))
        if guide['public_key']:
            z.writestr('server.pub',guide['public_key']+'\n')
        # Only a TLS *certificate* is public; never a private key.
        if engine=='slipstream':
            certificate=core.ROOT/'keys/slipstream-rust.crt'
            if certificate.is_file():z.writestr('slipstream-rust.crt',certificate.read_bytes())
            userguide=pathlib.Path(__file__).resolve().parent.parent/'docs/SLIPSTREAM_CLIENT_OPTIONS_FA_EN.md'
            if userguide.is_file():z.writestr('SLIPSTREAM_CLIENT_OPTIONS_FA_EN.md',userguide.read_text(encoding='utf-8'))
    return output.getvalue()
