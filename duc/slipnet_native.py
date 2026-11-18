"""Secret-free SlipNet/NoizDNS native CLI integration (Linux amd64).

Only public server data is placed in profile/bundle. The executable is an
unmodified, SHA256-verified official upstream release; no Python gateway or
DUC-owned client daemon is installed.

SlipNet's Go CLI has an *in-process SOCKS5 client*, not the same raw TCP
listener as original DNSTT. End-to-end Dante auth passthrough MUST be tested
independently; do not claim it merely from a ready server.
"""
from __future__ import annotations
import base64, hashlib, ipaddress, pathlib, re, urllib.request, urllib.error

REPO='anonvector/SlipNet'
TAG='v2.5.3'  # Upstream release with a published Linux amd64 CLI asset.
BINARY='slipnet-linux-amd64'
# Fixed SHA-256 of the v2.5.3 Linux CLI, independently listed on the
# SourceForge SlipNet mirror (not an upstream-signed attestation).
# Fail closed on a hash mismatch; never accept a mutable "latest" build.
PINNED_SHA256='1eb6a66df7a9d15e2260dd28d28655a3d5cebced8504509062ab614097f27534'
DOWNLOAD_URL=f'https://github.com/{REPO}/releases/download/{TAG}/{BINARY}'
MIRROR_URL=f'https://downloads.sourceforge.net/project/slipnet.mirror/{TAG}/{BINARY}'
MAX_BINARY=65_000_000


def profile_fields(domain: str, public_key: str, resolver='1.1.1.1:53', port=2080, stealth=True,
                   tunnel_type='sayedns', vaydns=None):
    if not isinstance(domain,str) or len(domain)>253 or not re.fullmatch(r'[A-Za-z0-9.-]+',domain) or '.' not in domain:
        raise ValueError('Invalid NoizDNS domain')
    if not isinstance(public_key,str) or not re.fullmatch(r'[0-9a-fA-F]{64}',public_key):
        raise ValueError('NoizDNS public key must be 64 hexadecimal characters')
    if type(port) is not int or not 1024<=port<=65535:
        raise ValueError('Invalid client port')
    if not isinstance(resolver,str) or not re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}:\d{1,5}',resolver):
        raise ValueError('Invalid resolver')
    addr,port_str=resolver.rsplit(':',1)
    ipaddress.IPv4Address(addr)
    if not 1<=int(port_str)<=65535:raise ValueError('Invalid DNS resolver port')
    if tunnel_type not in ('sayedns','dnstt','vaydns'):
        raise ValueError('Unsupported SlipNet DNS client mode')
    if stealth and tunnel_type!='sayedns':
        raise ValueError('Stealth is exclusive to sayedns')
    # Confirmed SlipNet CLI v18+ pipe-index schema (cli/main.go):
    #  1=sayedns; 3=domain; 4=resolvers; 8=local port; 9=listen host;
    # 11=Noise public key; 12/13=SOCKS credentials (EMPTY by default);
    # 22=DNS transport; 38=NoizDNS stealth; 39=query payload cap.
    f=['']*70
    f[0]='18';f[1]=tunnel_type;f[2]='DUC '+tunnel_type.upper()+(' Stealth' if stealth else '')
    f[3]=domain.lower();f[4]=resolver+':0'
    f[5]='0';f[6]='0';f[8]=str(port);f[9]='127.0.0.1';f[10]='0'
    f[11]=public_key.lower();f[12]='';f[13]=''
    f[22]='udp';f[38]='1' if stealth else '0';f[39]='0'
    if tunnel_type=='vaydns':
        config=vaydns or {}
        f[41]='1' if config.get('dnstt_compat',False) else '0'
        f[42]=str(config.get('record_type','txt'))
        f[43]=str(config.get('max_qname_len',101))
        f[44]=str(config.get('rps',0))
        f[45]=str(config.get('vay_idle_timeout',10))
        f[46]=str(config.get('vay_keepalive',2))
        f[47]=str(config.get('udp_timeout',2000))
        f[48]=str(config.get('max_num_labels',0))
        f[49]=str(config.get('client_id_size',8 if config.get('dnstt_compat',False) else 2))
    f[60]='roundrobin';f[61]='1' 
    return f


def profile_text(domain, public_key, resolver='1.1.1.1:53', port=2080, stealth=True, **kwargs):
    return '|'.join(profile_fields(domain,public_key,resolver,port,stealth,**kwargs))


def profile_uri(*a,**kw):
    return 'slipnet://'+base64.b64encode(profile_text(*a,**kw).encode('utf-8')).decode('ascii')


def launcher(tunnel_type="sayedns",default_resolver='1.1.1.1:53',default_port=2080):
    from .client_catalog import build_settings
    build_settings(default_resolver,default_port)
    # Entire client remains the native Go executable; this script only builds
    # the public URI at startup. Never spawns a gateway or accepts JSON.
    if tunnel_type not in ('sayedns','dnstt','vaydns'): raise ValueError('invalid client mode')
    return r'''#!/usr/bin/env bash
set -Eeuo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
[[ -x ./slipnet-linux-amd64 ]] || { echo 'Missing native SlipNet CLI executable' >&2; exit 1; }
[[ -f ./slipnet-profile.txt ]] || { echo 'Missing public SlipNet profile' >&2; exit 1; }
command -v base64 >/dev/null || { echo 'base64 is required' >&2; exit 1; }
URI="slipnet://$(base64 -w0 < ./slipnet-profile.txt)"
RESOLVER="${DUC_DNS_RESOLVER:-__DEFAULT_RESOLVER__}"
PORT="${DUC_CLIENT_PORT:-__DEFAULT_PORT__}"
[[ "$RESOLVER" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}:[0-9]{1,5}$ ]] || { echo 'Invalid resolver format' >&2; exit 2; }
[[ "$PORT" =~ ^[0-9]{4,5}$ ]] && (( PORT >= 1024 && PORT <= 65535 )) || { echo 'Invalid local TCP port' >&2; exit 2; }
echo 'Starting native SlipNet __MODE__ with explicit recursive DNS resolver.' 
echo 'Dante is authenticated on VPS. This public profile does NOT contain its credentials.'
exec ./slipnet-linux-amd64 --dns "$RESOLVER" --port "$PORT" "$URI"
'''.replace('__MODE__',tunnel_type).replace('__DEFAULT_RESOLVER__',default_resolver).replace('__DEFAULT_PORT__',str(default_port))


def auth_launcher(default_resolver='1.1.1.1:53',default_port=2080):
    from .client_catalog import build_settings
    build_settings(default_resolver,default_port)
    # Explicit opt-in fallback for SlipNet's documented SetSocksCredentials
    # injection (NOT transparent relay of credentials from local SOCKS client).
    # Credentials are not stored. WARNING: the encoded argv may be observable
    # to other processes of the same user; documented in README.
    return '''#!/usr/bin/env bash
set -Eeuo pipefail
set +x
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
[[ -x ./slipnet-linux-amd64 && -f ./slipnet-profile.txt ]] || { echo 'Missing SlipNet client/profile' >&2; exit 1; }
read -r -p 'Dante username: ' USERNAME
read -rs -p 'Dante password: ' PASSWORD; echo
if [[ -z "$USERNAME" || -z "$PASSWORD" || "$USERNAME" == *'|'* || "$PASSWORD" == *'|'* || "$USERNAME" == *$'\\n'* || "$PASSWORD" == *$'\\n'* ]]; then
  echo 'Invalid credentials for the pipe-delimited SlipNet format' >&2; exit 1
fi
IFS='|' read -r -a FIELDS < ./slipnet-profile.txt || true
[[ "${FIELDS[1]:-}" == 'sayedns' && "${FIELDS[38]:-}" == 1 ]] || { echo 'Not a NoizDNS Stealth profile' >&2; exit 1; }
FIELDS[12]="$USERNAME"; FIELDS[13]="$PASSWORD"
PROFILE=$(IFS='|'; printf '%s' "${FIELDS[*]}")
URI="slipnet://$(printf '%s' "$PROFILE" | base64 -w0)"
unset PROFILE PASSWORD USERNAME FIELDS
echo 'Dante credentials will be injected by native SlipNet; NOT passed through from the local SOCKS application.'
echo 'WARNING: base64-encoded credentials occur in this process command line. Use only on a trusted local account.'
exec ./slipnet-linux-amd64 --dns "${DUC_DNS_RESOLVER:-__DEFAULT_RESOLVER__}" --port "${DUC_CLIENT_PORT:-__DEFAULT_PORT__}" "$URI"
'''.replace('__DEFAULT_RESOLVER__',default_resolver).replace('__DEFAULT_PORT__',str(default_port))


def get_release_binary():
    """Fetch the exact v2.5.3 CLI with a fixed digest and no latest/API lookup.

    GitHub is tried first. A read-only SourceForge mirror is a fallback only
    for network/release-download errors; both have to match the SAME pinned
    SHA-256. A bad or corrupt downloaded binary aborts, not fallbacks.
    Returns bytes, tag, digest. Never downloads an APK or substituted filename.
    """
    errors=[]
    for url,origin in ((DOWNLOAD_URL,'official GitHub release'),
                       (MIRROR_URL,'SourceForge mirror')):
        request=urllib.request.Request(url,headers={
            'User-Agent':'DNS-Unified-Control/0.9.8',
            'Accept':'application/octet-stream'})
        try:
            with urllib.request.urlopen(request,timeout=120) as response:
                # A redirect to plaintext transport is never acceptable.
                final=response.geturl() if hasattr(response,'geturl') else url
                if not isinstance(final,str) or not final.startswith('https://'):
                    raise RuntimeError('Insecure redirect during SlipNet binary download')
                data=response.read(MAX_BINARY+1)
        except (OSError,TimeoutError,urllib.error.URLError) as exc:
            errors.append(f'{origin}: {type(exc).__name__}: {str(exc)[:110]}')
            continue
        if len(data)>MAX_BINARY or len(data)<100_000 or not data.startswith(b'\x7fELF'):
            raise RuntimeError(f'Invalid Linux amd64 ELF payload from {origin}; refusing client package')
        actual=hashlib.sha256(data).hexdigest()
        if actual.lower()!=PINNED_SHA256:
            raise RuntimeError(f'SlipNet v2.5.3 SHA-256 mismatch from {origin}; refusing client package')
        return data,TAG,actual
    raise RuntimeError('Could not fetch pinned SlipNet v2.5.3 Linux CLI: '+'; '.join(errors))


def readme(guide, source_tag=TAG, upstream_hash=''):
    return f'''DNS Unified Control — NoizDNS Stealth (native SlipNet CLI)

ENGINE: NoizDNS (SlipNet 'sayedns', stealth field 38 = 1)
DOMAIN: {guide['domain']}
PUBLIC KEY: {guide['public_key']}
UPSTREAM: https://github.com/anonvector/SlipNet/releases/tag/{source_tag}
PINNED SHA-256: {upstream_hash or PINNED_SHA256}

1. In the DUC panel select NoizDNS as the ONLY active DNS engine.
2. Stop the previous native client using localhost:2080.
3. Run: chmod +x ./slipnet-linux-amd64 ./run-noizdns.sh
4. Run: ./run-noizdns.sh (uses the chosen build resolver and port; override with DUC_DNS_RESOLVER=8.8.8.8:53 DUC_CLIENT_PORT=2080)
5. Configure v2rayN/FoxyProxy to 127.0.0.1:2080 SOCKS5.
6. First try credentials in the SOCKS app exactly as you used with Dante:
   curl -4 -v --connect-timeout 20 --max-time 90 \\
     --socks5-hostname 127.0.0.1:2080 --proxy-user USER:PASS https://api.ipify.org
   No secrets are embedded in the packaged public profile.

AUTH NOTE: SlipNet's native client handles SOCKS5 locally. Field tests on
2026-11-07: good SOCKS credentials returned HTTPS 200 via 1.1.1.1, bad
credentials were rejected, and no-auth was refused. VPS Dante journal
correlation has NOT been independently verified.
If the normal command fails at SOCKS auth, optionally run:
   ./run-noizdns-inject-auth.sh
That script prompts locally (not in the panel) and injects credentials via
SlipNet's documented SetSocksCredentials interface. The base64 URI in the
process command line temporarily contains those credentials; only use this
on a trusted computer. Never share process listings or the URI.
The local SOCKS authorization semantics may differ in injection mode.

Native NoizDNS uses DNS tunnel + in-process SOCKS; no external Python Gateway,
no extra proxy service, no client JSON. NoizDNS Stealth over 1.1.1.1:53 to the shared SOCKS backend was
field-tested on 2026-11-07; deployment changes require a new test.

This is a third-party AGPL-3.0 upstream binary. See upstream license.
No Dante password, private key, Cloudflare token or TOTP is inside this ZIP.
'''
