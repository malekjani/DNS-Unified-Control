"""Installer-only NoizDNS server bootstrap; no engine activation, no client gateway.

Uses the separate anonvector/dnstt fork server built as `noizdns-server`.
The server accepts normal DNSTT and the NoizDNS stealth variants spoken by
proper NoizDNS clients; a vanilla DNSTT client is not a stealth-mode test.

Changes confined to NoizDNS binary/keys and the legacy NoizDNS default backend.
Existing non-default targets, established keys, Dante, active DNS service,
network/firewall/DNS configuration, SSH, and other engines are never modified.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
from . import core, provision

BINARY = pathlib.Path('/usr/local/bin/noizdns-server')
TARGET = '127.0.0.1:1080'
LEGACY_TARGET = '127.0.0.1:22'


def _x25519_pub_from_private(private_hex: str) -> str:
    """RFC 7748 X25519 base-point multiplication, only to validate a keypair.

    This derives the PUBLIC key; the private key never leaves the root process.
    No third-party crypto package or external secret-bearing CLI output needed.
    """
    private=bytearray.fromhex(private_hex)
    if len(private)!=32: raise ValueError('expected a 32-byte Noise/X25519 private key')
    private[0] &= 248
    private[31] &= 127
    private[31] |= 64
    k=int.from_bytes(private,'little')
    prime=2**255-19
    x1=9
    x2,z2,x3,z3,swap=1,0,x1,1,0
    for t in range(254,-1,-1):
        kt=(k>>t)&1
        swap^=kt
        if swap: x2,x3=x3,x2; z2,z3=z3,z2
        swap=kt
        a=(x2+z2)%prime
        aa=(a*a)%prime
        b=(x2-z2)%prime
        bb=(b*b)%prime
        e=(aa-bb)%prime
        c=(x3+z3)%prime
        d=(x3-z3)%prime
        da=(d*a)%prime
        cb=(c*b)%prime
        x3=((da+cb)**2)%prime
        z3=(x1*(da-cb)**2)%prime
        x2=(aa*bb)%prime
        z2=(e*(aa+121665*e))%prime
    if swap: x2,x3=x3,x2; z2,z3=z3,z2
    return ((x2*pow(z2,prime-2,prime))%prime).to_bytes(32,'little').hex()


def ensure_identity():
    """Preserve existing keys; repair missing public from private without rotation.

    Reject symlinks, invalid hex, wrong public key, and orphaned public keys.
    """
    directory=core.ROOT/'keys'
    directory.mkdir(mode=0o700,parents=True,exist_ok=True)
    private=directory/'noizdns.key'
    public=directory/'noizdns.pub'
    if private.is_symlink() or public.is_symlink():
        raise RuntimeError('NoizDNS keys must be regular files, not symlinks')
    if not private.exists():
        if public.exists(): raise RuntimeError('Orphaned NoizDNS public key; refusing key rotation')
        from . import worker
        worker.generate_key('noizdns')
    if not private.is_file(): raise RuntimeError('NoizDNS private key missing')
    # Keep current private identity, including if older installer had loose perms.
    private.chmod(0o600)
    raw=private.read_text('ascii').strip().lower()
    if not re.fullmatch(r'[0-9a-f]{64}',raw):
        raise RuntimeError('NoizDNS private key not valid 32-byte hex')
    expected=_x25519_pub_from_private(raw)
    if public.exists():
        if not public.is_file(): raise RuntimeError('NoizDNS public key is not a regular file')
        actual=public.read_text('ascii').strip().lower()
        if actual!=expected:
            raise RuntimeError('NoizDNS public key does not match PRIVATE key; refusing overwrite')
    else:
        # Public identity is deterministic; no key rotation is necessary.
        fd=os.open(public,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o644)
        with os.fdopen(fd,'w') as f:
            f.write(expected+'\n')
    public.chmod(0o644)
    return expected


def inspect_server_assets():
    errors=[]
    private=core.ROOT/'keys/noizdns.key'
    public=core.ROOT/'keys/noizdns.pub'
    binary_present=BINARY.is_file() and not BINARY.is_symlink() and os.access(BINARY,os.X_OK)
    if not binary_present:
        errors.append('Missing executable /usr/local/bin/noizdns-server')
    else:
        try:
            with BINARY.open('rb') as f:
                if f.read(4)!=b'\x7fELF':errors.append('NoizDNS server binary must be Linux ELF')
            # Different upstream forks may lack -udp; we build this specific fork.
            r=subprocess.run([str(BINARY),'-help'],capture_output=True,text=True,timeout=8,check=False)
            if '-udp' not in (r.stdout+r.stderr):
                errors.append('NoizDNS binary does not advertise native -udp server mode')
        except (OSError,subprocess.SubprocessError) as ex:
            errors.append('Cannot verify NoizDNS server CLI: '+type(ex).__name__)
        from .noiz_provenance import check as provenance_check
        if not provenance_check(BINARY):
            errors.append('NoizDNS build provenance or binary SHA256 is missing/mismatched')
    private_mode_ok=False
    public_ok=False
    try:
        if not private.is_file() or private.is_symlink():raise ValueError('private key missing or symlink')
        private_mode_ok=stat.S_IMODE(private.stat().st_mode)==0o600
        if not private_mode_ok:errors.append('NoizDNS private key must have permission 0600')
        private_hex=private.read_text('ascii').strip().lower()
        if not re.fullmatch(r'[0-9a-f]{64}',private_hex):raise ValueError('not 32-byte hexadecimal key')
        if not public.is_file() or public.is_symlink():raise ValueError('public key missing or symlink')
        public_ok=public.read_text('ascii').strip().lower()==_x25519_pub_from_private(private_hex)
        if not public_ok:errors.append('Public key does not match saved private key')
    except (OSError,UnicodeError,ValueError) as ex:
        errors.append('NoizDNS Noise keypair invalid: '+str(ex)[:90])
    return {'ok':not errors,'binary':str(BINARY), 'binary_present':binary_present,
            'private_key_mode_ok':private_mode_ok,'public_key_ready':public_ok,'issues':errors}


def migrate_default_backend():
    """Migrate ONLY legacy NoizDNS :22 default; preserve all other profiles.

    Backup in shared-backend-previous.json allows a later restore through the
    authenticated panel. This never restarts a running unit.
    """
    from . import unified
    with core.switch_lock():
        if core.is_active('noizdns'):
            return 'preserved-running'
        data=core.profiles()
        if data['noizdns']['target']!=LEGACY_TARGET:
            return 'already-default-or-custom'
        previous={}
        if unified.BACKUP.exists():
            previous=json.loads(unified.BACKUP.read_text())
            if not isinstance(previous,dict):
                raise RuntimeError('Existing shared-backend-previous.json invalid; refusing update')
        if 'noizdns' not in previous:
            previous['noizdns']=LEGACY_TARGET
            core.atomic_json(unified.BACKUP,previous)
        data['noizdns']['target']=TARGET
        core.atomic_json(core.ROOT/'profiles.json',data)
    return 'migrated-legacy-target-to-shared-dante'


def bootstrap():
    if os.geteuid()!=0:raise PermissionError('NoizDNS install requires root')
    active_before=core.list_active()
    result=provision.execute(only=('noizdns',))['engines']['noizdns']
    if result.get('state') in ('failed','requires-review'):
        raise RuntimeError('NoizDNS source install incomplete: '+result.get('message',''))
    # If installation reused an already present binary, keys still need
    # consistency verification (including public/private matching).
    ensure_identity()
    check=inspect_server_assets()
    if not check['ok']:
        raise RuntimeError('NoizDNS assets invalid: '+'; '.join(check['issues']))
    mode=migrate_default_backend()
    active_after=core.list_active()
    if active_after!=active_before:
        raise RuntimeError('Active tunnel engine changed during NoizDNS bootstrap')
    return {'assets':check,'installer_state':result['state'],
            'backend':core.profiles()['noizdns']['target'],'backend_action':mode,
            'active_dns':active_after}


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true',help='read-only server-asset validation')
    args=parser.parse_args(argv)
    try:
        data=inspect_server_assets() if args.check else bootstrap()
        check=data if args.check else data['assets']
        print('NoizDNS standalone server:', 'READY' if check['ok'] else 'INCOMPLETE')
        print('  binary:',check['binary'])
        print('  private Noise/X25519 key (0600):','OK' if check['private_key_mode_ok'] else 'MISSING/UNSAFE')
        print('  matching public key:','OK' if check['public_key_ready'] else 'MISSING/INVALID')
        if not args.check:
            print('  installation:',data['installer_state'])
            print('  backend:',data['backend'],'('+data['backend_action']+')')
            print('  DNS active unchanged:',', '.join(data['active_dns']) or 'none')
        else:
            for item in check['issues']:print('  ISSUE:',item)
        print('  NOTE: NoizDNS stealth client and end-to-end link still need field verification.')
        return 0 if check['ok'] else 1
    except Exception as ex:
        print('NOIZDNS INSTALL ERROR: '+type(ex).__name__+': '+str(ex)[:600],file=sys.stderr)
        return 1

if __name__=='__main__':
    raise SystemExit(main())
