"""Bootstrap Soar server assets from the DNS Unified installer (not from client UI).

No DNS engine switch, no Dante restart, no firewall edits and no key rotation.
This verifies only *server installation assets*, not operational readiness:
real delegation, Dante availability and client connectivity are separate.
"""
from __future__ import annotations
import argparse
import os
import pathlib
import subprocess
import stat
import sys
import base64
from . import core, provision, soar_secure

BINARY = pathlib.Path('/usr/local/bin/duc-soar-server')


def inspect_server_assets():
    private = core.ROOT / 'keys/soar.key'
    public = core.ROOT / 'keys/soar.pub'
    errors=[]
    if not BINARY.is_file() or not os.access(BINARY,os.X_OK):
        errors.append('Restricted duc-soar-server binary is missing/not executable')
    else:
        try:
            with BINARY.open('rb') as f:
                if f.read(4)!=b'\x7fELF':
                    errors.append('Restricted Soar binary is not Linux ELF')
        except OSError as e:
            errors.append('Cannot inspect restricted Soar binary: '+str(e))
    try:
        if not private.is_file() or private.is_symlink():
            errors.append('Missing or unsafe keys/soar.key')
        else:
            mode=stat.S_IMODE(private.stat().st_mode)
            if mode!=0o600:
                errors.append(f'Private key must be mode 0600, got {mode:04o}')
            if len(base64.b64decode(private.read_text('ascii').strip(),validate=True))!=32:
                errors.append('Soar private key must be a 32-byte Ed25519 seed')
    except (OSError,ValueError,UnicodeError) as e:
        errors.append('Invalid Soar private key: '+type(e).__name__)
    try:
        if not public.is_file() or public.is_symlink() or not soar_secure.public_key():
            errors.append('Missing or invalid keys/soar.pub')
        elif private.is_file() and not private.is_symlink() and BINARY.is_file():
            # Verify identity continuity even if the provisioner classified the
            # existing assets as ready and therefore skipped key preparation.
            # stdout contains only PUBLIC key; private seed never reaches logs.
            derived=subprocess.run([str(BINARY),'pubkey',str(private)],
                                   capture_output=True,text=True,timeout=15,check=True).stdout.strip()
            if derived!=public.read_text('ascii').strip():
                errors.append('Soar public key does not match the preserved private key')
    except (OSError,ValueError,subprocess.SubprocessError,UnicodeError) as e:
        errors.append('Invalid Soar public key or identity: '+type(e).__name__)
    return {'ok':not errors,'binary':str(BINARY),'private_key_present':private.is_file(),
            'private_key_mode_ok':private.is_file() and not private.is_symlink() and stat.S_IMODE(private.stat().st_mode)==0o600,
            'public_key_ready':bool(soar_secure.public_key()),'issues':errors,
            'running_engine_unchanged':True}


def bootstrap():
    if os.geteuid()!=0:
        raise PermissionError('Installer must run as root')
    before=core.list_active()
    # One targeted, idempotent install path shared with the provisioner. It
    # downloads Go toolchain/source if absent, installs restricted server and
    # generates/verifies Soar Ed25519 keys. Other engines are never installed.
    result=provision.execute(only=('soar',))
    entry=result['engines']['soar']
    report=inspect_server_assets()
    after=core.list_active()
    if after!=before:
        raise RuntimeError('DNS engine changed unexpectedly during Soar bootstrap')
    if entry.get('state') in ('failed','requires-review') or not report['ok']:
        raise RuntimeError('Soar installation incomplete: '+entry.get('message','')+'; '+ '; '.join(report['issues']))
    return {'installation':entry['state'],'server_assets':report,
            'operational_preflight':entry.get('readiness',{}),
            'active_dns':after}


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true',help='read-only inspection; no install')
    args=parser.parse_args(argv)
    try:
        result=inspect_server_assets() if args.check else bootstrap()
        assets=result if args.check else result['server_assets']
        print('Restricted Soar server:', 'READY' if assets['ok'] else 'INCOMPLETE')
        print('  binary:', assets['binary'])
        print('  private Ed25519 key (0600):', 'OK' if assets['private_key_mode_ok'] else 'MISSING/UNSAFE')
        print('  public Ed25519 key:', 'OK' if assets['public_key_ready'] else 'MISSING/INVALID')
        if not args.check:
            print('  installer state:',result['installation'])
            print('  active DNS engine unchanged:', ', '.join(result['active_dns']) or 'none')
        for issue in assets['issues']:
            print('  ERROR:', issue)
        return 0 if assets['ok'] else 1
    except Exception as exc:
        print('SOAR INSTALL ERROR: '+type(exc).__name__+': '+str(exc)[:650],file=sys.stderr)
        return 1

if __name__=='__main__':
    raise SystemExit(main())
