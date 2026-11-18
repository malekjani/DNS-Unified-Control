"""Pinned AliRezaBeigy SlipStream release importer for DNS Unified Control.

Never invokes the deployment script. Does not touch systemd units, firewall,
port 53, Caddy, routes or proxy daemons. The existing exclusive runner is owner.
"""
from __future__ import annotations
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import urllib.request

from . import core

REPO = 'AliRezaBeigy/slipstream-rust-deploy'
TAG = '42e3e75'  # immutable release *tag name*; verify SHA-256 independently
BASE = f'https://github.com/{REPO}/releases/download/{TAG}'
BINARIES = {
    'server': {
        'asset': 'slipstream-server-linux-amd64',
        'sha256': 'e4363c228c0b5c6ab80a75726f87e40dba55eef6d4a148a839972a9e5fc977a5',
        'target': Path('/usr/local/bin/slipstream-rust-server'),
        'flags': ('--domain','--dns-listen-host','--dns-listen-port','--target-address',
                  '--cert','--key','--reset-seed','--max-connections','--idle-timeout-seconds'),
    },
    'client': {
        'asset': 'slipstream-client-linux-amd64',
        'sha256': '677eb993a8033f1bbec1739b36c7d233b23da98f35b00e1d9181f7c0b994e0b1',
        'target': Path('/usr/local/bin/slipstream-rust-client'),
        'flags': ('--domain','--resolver','--tcp-listen-port','--cert',
                  '--congestion-control','--keep-alive-interval'),
    },
}
MANIFEST_NAME = 'slipstream-ali-release.json'
MAX_BYTES = 30 * 1024 * 1024


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def is_x86_64_elf(path: Path) -> bool:
    with path.open('rb') as f:
        header=f.read(24)
    return len(header)>=20 and header[:6]==b'\x7fELF\x02\x01' and struct.unpack_from('<H',header,18)[0]==62


def check_binary(path: Path, kind: str, *, cli=True) -> None:
    info=BINARIES[kind]
    if not path.is_file() or path.is_symlink():
        raise RuntimeError(f'{kind} is not a regular file: {path}')
    if not 100000 < path.stat().st_size <= MAX_BYTES:
        raise RuntimeError(f'{kind} size outside allowed range')
    if file_sha256(path)!=info['sha256']:
        raise RuntimeError(f'{kind} SHA-256 does not match pinned AliRezaBeigy release')
    if not is_x86_64_elf(path):
        raise RuntimeError(f'{kind} is not an ELF64 x86_64 executable')
    if cli:
        result=subprocess.run([str(path),'--help'],capture_output=True,text=True,timeout=12,check=False)
        output=result.stdout+'\n'+result.stderr
        if result.returncode!=0:
            raise RuntimeError(f'{kind} --help failed (possible missing runtime libraries)')
        for flag in info['flags']:
            if flag not in output:
                raise RuntimeError(f'{kind} release lacks required flag {flag}; no installation')


def download(kind: str, dest: Path):
    url=f"{BASE}/{BINARIES[kind]['asset']}"
    req=urllib.request.Request(url,headers={'User-Agent':'DNS-Unified-Control/0.7.0 AliReleaseImporter',
                                           'Accept':'application/octet-stream'})
    # urllib verifies HTTPS certificates and follows GitHub release redirects.
    with urllib.request.urlopen(req,timeout=45) as response, dest.open('wb') as out:
        if not response.geturl().startswith('https://'):
            raise RuntimeError('Refusing non-HTTPS release redirect')
        size=0
        while chunk:=response.read(1024*1024):
            size+=len(chunk)
            if size>MAX_BYTES:raise RuntimeError('Downloaded asset too large')
            out.write(chunk)
    dest.chmod(0o700)
    check_binary(dest,kind)


def standalone_conflict():
    # The upstream deploy script owns this independent unit; never touch it.
    for name in ('slipstream-rust-server.service','slipstream-restore-iptables.service'):
        state=subprocess.run(['systemctl','is-active','--quiet',name],capture_output=True,check=False)
        enabled=subprocess.run(['systemctl','is-enabled','--quiet',name],capture_output=True,check=False)
        if state.returncode==0 or enabled.returncode==0:
            raise RuntimeError(f'Independent {name} is active/enabled; resolve manually before importing')


def install():
    if os.geteuid()!=0:raise PermissionError('Root required')
    if os.uname().machine not in ('x86_64','amd64'):
        raise RuntimeError('This pinned release is Linux x86_64 only')
    # Enforce the same low-resource disk/architecture gate used by web preflight.
    # Small RAM/CPU is a warning, since this importer never compiles Rust.
    hardware = preflight()
    if hardware['blocked']:
        raise RuntimeError(hardware['assessment'])
    core.STATE.mkdir(parents=True,exist_ok=True)
    lock=core.STATE/'provision.lock'
    with lock.open('a+') as held:
        try:fcntl.flock(held.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise RuntimeError('Another DUC installation/switch is in progress')
        # Acquire shared switch lock too, so a user switch cannot sneak in during the check.
        with core.switch_lock():
            if core.is_active('slipstream'):
                raise RuntimeError('SlipStream is active; refusing to replace/inspect live executables')
            standalone_conflict()
        pending=[]
        for kind,info in BINARIES.items():
            dest=info['target']
            if dest.exists() or dest.is_symlink():
                check_binary(dest,kind)
                print(f'PRESERVED pinned {kind}: {dest}',flush=True)
            else:
                pending.append(kind)
        with tempfile.TemporaryDirectory(prefix='duc-ali-release-') as folder:
            tmp=Path(folder)
            # Download and verify ALL missing assets before installing ANY of them.
            for kind in pending:
                print(f'DOWNLOADING pinned {kind}: {BINARIES[kind]["asset"]}',flush=True)
                download(kind,tmp/kind)
            for kind in pending:
                target=BINARIES[kind]['target']
                target.parent.mkdir(parents=True,exist_ok=True)
                # Atomic no-overwrite creation: protect preexisting files, even on a rerun.
                import errno
                stage=target.with_name(f'.{target.name}.duc-staged-{os.getpid()}')
                try:
                    shutil.copyfile(tmp/kind,stage)
                    stage.chmod(0o755)
                    if target.exists() or target.is_symlink():
                        raise RuntimeError(f'{target} appeared while installing; refusing overwrite')
                    # hard-link creation is atomic and fails if destination already exists.
                    os.link(stage,target)
                    print(f'INSTALLED pinned {kind}: {target}',flush=True)
                finally:
                    stage.unlink(missing_ok=True)
        # No binary was replaced. Only now provision persistent TLS files.
        prep=Path('/opt/dns-unified-control/scripts/prepare-slipstream-rust.sh')
        if not prep.is_file():raise RuntimeError('Panel TLS preparation script unavailable; rerun after upgrading panel')
        subprocess.run(['bash',str(prep)],check=True,timeout=50)
        manifest={'repository':REPO,'tag':TAG,'mode':'imported-binaries-exclusive-panel',
                  'server_sha256':BINARIES['server']['sha256'],
                  'client_sha256':BINARIES['client']['sha256'],
                  'standalone_service':False,'iptables_changes':False,
                  'source_build':False}
        core.atomic_json(core.STATE/MANIFEST_NAME,manifest)
        from .core import check_ready
        state=check_ready('slipstream')
        print('READINESS:',json.dumps(state,ensure_ascii=False),flush=True)
        if not state['ready']:
            raise RuntimeError('Binaries installed but readiness incomplete; do not switch engine')
        print('COMPLETE: imported matched AliRezaBeigy server/client; active DNS engine unchanged',flush=True)
        return manifest



def preflight():
    """Read-only web/CLI hardware assessment and pinned-release status.

    Does not fetch releases, generate secrets or touch running services.
    """
    import psutil
    mem=psutil.virtual_memory()
    swap=psutil.swap_memory()
    disk=shutil.disk_usage('/usr/local/bin')
    cpus=os.cpu_count() or 1
    installed={}
    for kind,info in BINARIES.items():
        path=info['target']
        if not path.exists() and not path.is_symlink():
            installed[kind]={'state':'missing'}
            continue
        try:
            check_binary(path,kind,cli=False)
            installed[kind]={'state':'verified','sha256':info['sha256']}
        except (RuntimeError,OSError,PermissionError) as exc:
            installed[kind]={'state':'invalid','reason':str(exc)[:180]}
    limited=mem.total < 2*1024**3 or mem.available < 700*1024**2 or cpus < 2
    min_disk=350*1024**2
    blocked=disk.free < min_disk or os.uname().machine not in ('x86_64','amd64')
    return {
      'engine':'slipstream','repository':REPO,'tag':TAG,
      'cpu_count':cpus,'ram_total_mib':round(mem.total/1024**2),
      'ram_available_mib':round(mem.available/1024**2),
      'swap_mib':round(swap.total/1024**2),'disk_free_mib':round(disk.free/1024**2),
      'limited':limited,'blocked':blocked,
      'assessment': ('Blocked: require Linux AMD64 and >=350 MiB free disk' if blocked else
                     'Low-resource VPS: use pinned prebuilt binaries, not Rust source compilation' if limited else
                     'Hardware adequate for pinned prebuilt binaries; no source compilation needed'),
      'binaries':installed,'active_engine':core.list_active(),
      'changes':'Verify/download pinned server and client, preserve TLS/keys, no engine start, no firewall, no standalone service',
      'safety':'Explicit authenticated web confirmation required for job; CLI command is already explicit authorization'
    }


def main():
    p=argparse.ArgumentParser(description='Pinned AliRezaBeigy binaries; ONLY existing DNS Unified Control systemd manages them')
    g=p.add_mutually_exclusive_group(required=True)
    g.add_argument('--install',action='store_true')
    g.add_argument('--verify',action='store_true')
    g.add_argument('--preflight',action='store_true')
    args=p.parse_args()
    if args.preflight:
        print(json.dumps(preflight(),indent=2));return
    if args.install:
        print(json.dumps(install(),indent=2));return
    for kind,info in BINARIES.items():
        check_binary(info['target'],kind)
        print('VERIFIED',kind,info['sha256'])

if __name__=='__main__':
    main()
