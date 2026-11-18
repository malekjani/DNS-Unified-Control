"""Fixed-source, one-engine-at-a-time installer/client-builder (root systemd transient job)."""
from __future__ import annotations
import hashlib, json, os, pathlib, platform, shutil, subprocess, sys, tempfile, time, zipfile
from . import core, jobs, workflow

REPOS = {'dnstt':('net2share/dnstt','./dnstt-server','dnstt-server'),
         'noizdns':('anonvector/dnstt','./dnstt-server','noizdns-server'),
         'master':('masterking32/MasterDnsVPN','./cmd/server','masterdnsvpn-server'),
         'vaydns':('net2share/vaydns','./vaydns-server','vaydns-server'),
         'soar':('getlantern/soar','./cmd/soar-server','soar-server')}


def run(args,cwd=None,timeout=900,env=None):
    print('COMMAND:', ' '.join(str(x) for x in args[:5]),flush=True)
    r=subprocess.run(args,cwd=cwd,env=env,timeout=timeout,stdout=subprocess.PIPE,
                     stderr=subprocess.STDOUT,text=True,check=False)
    # Report output as bounded worker journald lines; never log credentials.
    if r.returncode:
        print(r.stdout[-1400:],flush=True)
        raise RuntimeError(f'{args[0]} failed with exit {r.returncode}')
    return r.stdout


def source(engine):
    repo,_,_=REPOS[engine]
    root=core.STATE/'upstream-src'/engine
    root.parent.mkdir(parents=True,exist_ok=True)
    server_checkout=pathlib.Path('/root/dns-engines/dnstt') if engine=='dnstt' else None
    if server_checkout and (server_checkout/'.git').exists():
        origin=run(['git','remote','get-url','origin'],cwd=server_checkout,timeout=10).strip()
        if origin in ('https://github.com/net2share/dnstt.git','https://github.com/net2share/dnstt'):
            clean=run(['git','status','--porcelain'],cwd=server_checkout,timeout=10)
            if not clean.strip():
                commit=run(['git','rev-parse','HEAD'],cwd=server_checkout,timeout=10).strip()
                print('REUSING REVIEWED SOURCE:',commit,flush=True)
                return server_checkout,commit
    pin=None
    if server_checkout and (server_checkout/'.git').exists():
        try:pin=run(['git','rev-parse','HEAD'],cwd=server_checkout,timeout=10).strip()
        except Exception:pass
    if root.exists():
        if not (root/'.git').is_dir(): raise RuntimeError(f'{root} exists but is not a git repository')
        actual=run(['git','remote','get-url','origin'],cwd=root,timeout=10).strip()
        if actual not in ('https://github.com/'+repo+'.git','https://github.com/'+repo):
            raise RuntimeError('Source origin mismatch; refusing untrusted checkout')
        if run(['git','status','--porcelain'],cwd=root,timeout=10).strip():
            raise RuntimeError('Source checkout was modified; manual review required')
        # Avoid updating an already reviewed source tree without operator review.
    else:
        run(['git','clone','--depth','1','https://github.com/'+repo+'.git',str(root)],timeout=180)
    if pin:
        cached=run(['git','rev-parse','HEAD'],cwd=root,timeout=10).strip()
        if cached!=pin:
            run(['git','fetch','--depth','1','origin',pin],cwd=root,timeout=90)
            run(['git','checkout','--detach',pin],cwd=root,timeout=20)
    commit=run(['git','rev-parse','HEAD'],cwd=root,timeout=10).strip()
    print('SOURCE:',repo,commit,flush=True)
    return root,commit


# The transient systemd worker does not necessarily have HOME, GOPATH or
# GOMODCACHE. Go 1.22 rejects module builds without an explicit module cache.
# Keep caches outside /root so builds work in a minimal service environment.
GO_CACHE_ROOT = pathlib.Path('/var/cache/dns-unified/go')


def go_build(src,subdir,dest,allow_mod_updates=False):
    if shutil.which('go') is None: raise RuntimeError('Go not installed. Install golang-go on VPS before starting this task.')
    gopath = GO_CACHE_ROOT
    module_cache = gopath/'pkg'/'mod'
    build_cache = gopath/'build-cache'
    for folder in (gopath, module_cache, build_cache):
        folder.mkdir(parents=True, exist_ok=True, mode=0o700)
        folder.chmod(0o700)
    env=os.environ.copy()
    env.update({'GOPATH':str(gopath), 'GOMODCACHE':str(module_cache),
                'GOCACHE':str(build_cache), 'GOMAXPROCS':'1',
                'CGO_ENABLED':'0','GOFLAGS':'-p=1','GOTOOLCHAIN':'auto'})
    run(['go','build',*(['-mod=mod'] if allow_mod_updates else []),'-p','1','-trimpath','-o',str(dest),subdir],cwd=src,env=env,timeout=900)
    if dest.stat().st_size<100000 or dest.open('rb').read(4)!=b'\x7fELF':
        raise RuntimeError('Unexpected output: not a compiled Linux ELF binary')
    dest.chmod(0o755)


def build_soar_dedicated(src, entry, out):
    """Compile a Soar-native executable linked to the exact locally cached upstream source.

    This runs in a separate temporary module to avoid dirtying the upstream git checkout.
    The client is one native Go process; no Python gateway or extra SOCKS proxy.
    """
    local=pathlib.Path(__file__).resolve().parent.parent/'soar-src'/entry
    if not local.is_file():raise RuntimeError('Missing audited Soar build source')
    with tempfile.TemporaryDirectory(prefix='duc-soar-build-') as tmp:
        td=pathlib.Path(tmp)
        (td/'main.go').write_bytes(local.read_bytes())
        # Local replace ties the binary to the same Go upstream source/commit as the server.
        (td/'go.mod').write_text('module duc.local/soar-client-fixed\n\ngo 1.25.0\n\nrequire github.com/getlantern/soar v0.0.0\nreplace github.com/getlantern/soar => '+str(src)+'\n')
        # go may update go.mod; the temporary module is intentionally discarded.
        # Go module downloads and toolchain use the existing bounded systemd worker.
        go_build(td,'.',out,allow_mod_updates=True)


def generate_key(engine):
    directory=core.ROOT/'keys';directory.mkdir(parents=True,exist_ok=True)
    priv=directory/f'{engine}.key';pub=directory/f'{engine}.pub'
    if priv.exists():
        print('Preserving existing private key; no regeneration.',flush=True)
        return
    if pub.exists():raise RuntimeError('Public key already exists but private key does not; manual recovery needed')
    binary=shutil.which(engine+'-server')
    if not binary: raise RuntimeError('Server binary not found after build')
    run([binary,'-gen-key','-privkey-file',str(priv),'-pubkey-file',str(pub)],timeout=20)
    priv.chmod(0o600);pub.chmod(0o644)


def install_server_raw(engine):
    if core.is_active(engine):
        raise RuntimeError('Engine is active; stop it in Exclusive Mode first')
    if engine=='soar':
        src,commit=source('soar')
        with tempfile.TemporaryDirectory(prefix='duc-soar-server-') as tmp:
            out=pathlib.Path(tmp)/'duc-soar-server'
            build_soar_dedicated(src,'server.go',out)
            run(['install','-o','root','-g','root','-m','0755',str(out),'/usr/local/bin/duc-soar-server'],timeout=30)
        from .soar_secure import ensure_keys
        ensure_keys()
        return {'source_commit':commit,'message':'Restricted Soar server and Ed25519 keys ready. DNS engine not started.'}
    if engine in REPOS:
        repo,subdir,binary=REPOS[engine]
        src,commit=source(engine)
        with tempfile.TemporaryDirectory(prefix='duc-bin-') as temp:
            out=pathlib.Path(temp)/binary
            go_build(src,subdir,out)
            run(['install','-o','root','-g','root','-m','0755',str(out),'/usr/local/bin/'+binary],timeout=20)
        if engine=='dnstt': generate_key('dnstt')
        if engine=='noizdns':
            from .noiz_provenance import save
            save('/usr/local/bin/noizdns-server',commit)
            generate_key('noizdns')
        if engine=='vaydns': generate_key('vaydns')
        # Soar direct mode intentionally not enabled (unauthenticated public proxy).
        return {'source_commit':commit, 'message':binary+' installed. Review preflight; activation is separate.'}
    if engine in ('iodine','dns2tcp'):
        run(['apt-get','update'],timeout=240)
        run(['apt-get','install','-y',engine],timeout=300,
            env=dict(os.environ,DEBIAN_FRONTEND='noninteractive'))
        keyname='iodine.pass' if engine=='iodine' else 'dns2tcp.key'
        path=core.ROOT/'keys'/keyname
        path.parent.mkdir(parents=True,exist_ok=True)
        if not path.exists():
            import secrets
            fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,'w') as f:f.write(secrets.token_urlsafe(22)[:32]+'\n')
        return {'message':f'{engine} installed; secret preserved/generated (never sent to web UI).'}
    raise RuntimeError('Engine requires manual review; no unattended installer')



def install_server(engine):
    if engine == 'slipstream':
        # Pinned AliRezaBeigy importer is idempotent; it never starts a tunnel,
        # makes firewall rules, or enables an upstream standalone systemd unit.
        from . import slipstream_ali
        result = slipstream_ali.install()
        return {'message':f"Verified pinned {result['repository']}@{result['tag']} (no activation)",
                'source_commit':result['tag']}
    # Same registry, secrets, reports, and idempotency as upgrade --install-missing.
    from . import provision
    result = provision.execute(only=(engine,))['engines'][engine]
    if result['state']=='failed':
        raise RuntimeError(result['message'])
    return {'message':f"{result['state']}: {result.get('message','')}",
            'source_commit':result.get('source_commit','')}


def build_client(engine,resolver='1.1.1.1:53',local_port=2080):
    from .client_catalog import build_settings
    settings=build_settings(resolver,local_port)
    resolver,local_port=settings['resolver'],settings['port']
    if platform.machine()!='x86_64':raise RuntimeError('Only Linux x86_64 binary packages supported')
    with tempfile.TemporaryDirectory(prefix='duc-client-') as temp:
        td=pathlib.Path(temp)
        if engine=='soar':
            from .soar_secure import public_key
            pk=public_key()
            if not pk:raise RuntimeError('Soar public key missing: server bootstrap in install.sh / upgrade.sh failed')
            src,commit=source('soar')
            exe=td/'soar-client'
            build_soar_dedicated(src,'client.go',exe)
            extra={'server.pub':pk+'\n',
                   'UPSTREAM.txt':f'Native client linked to getlantern/soar Go module at commit {commit}\n'}
        elif engine=='dnstt':
            src,commit=source('dnstt')
            exe=td/'dnstt-client'
            go_build(src,'./dnstt-client',exe)
            pk=workflow.public_key('dnstt')
            if not pk:raise RuntimeError('Missing 64-hex DNSTT public key; generate server keypair first')
            extra={'server.pub':pk+'\n'}
        elif engine=='vaydns':
            src,commit=source('vaydns')
            exe=td/'vaydns-client'
            go_build(src,'./vaydns-client',exe)
            pk=workflow.public_key('vaydns')
            if not pk:raise RuntimeError('Missing 64-hex VayDNS public key; generate server keypair first')
            extra={'server.pub':pk+'\n'}
        elif engine=='noizdns':
            from . import slipnet_native
            pk=workflow.public_key('noizdns')
            if not pk:raise RuntimeError('NoizDNS public key missing; run server installation first')
            c=core.profiles()['noizdns']
            if c.get('target')!='127.0.0.1:1080':
                raise RuntimeError('NoizDNS target is not shared authenticated Dante; fix profile first')
            data,commit,up_hash=slipnet_native.get_release_binary()
            exe=td/'slipnet-linux-amd64'
            exe.write_bytes(data);exe.chmod(0o755)
            guide=workflow.build_client_guide('noizdns',resolver,local_port)
            extra={
                'slipnet-profile.txt':slipnet_native.profile_text(c['domain'],pk,resolver,local_port)+'\n',
                'run-noizdns.sh':slipnet_native.launcher(default_resolver=resolver,default_port=local_port),
                'run-noizdns-inject-auth.sh':slipnet_native.auth_launcher(resolver,local_port),
                'UPSTREAM.txt':f'https://github.com/anonvector/SlipNet/releases/tag/{commit}\nasset SHA256={up_hash}\n',
                'NOIZDNS-STEALTH-README.txt':slipnet_native.readme(guide,commit,up_hash),
            }
        elif engine=='master':
            from .runner import replace_keys
            src,commit=source('master')
            template=src/'client_config.toml.simple'
            if not template.is_file():
                raise RuntimeError('Master upstream client config template missing')
            secret_path=core.ROOT/'keys/master.key'
            if not secret_path.is_file():
                raise RuntimeError('Master shared key missing; run installer first')
            secret=secret_path.read_text().strip()
            if not (32 <= len(secret) <= 128 and all(ch in '0123456789abcdefABCDEF' for ch in secret)):
                raise RuntimeError('Master encryption key has an unexpected format')
            c=core.profiles()['master']
            config=replace_keys(template.read_text(),{
                'DOMAINS':[c['domain']], 'ENCRYPTION_KEY':secret,
                'DATA_ENCRYPTION_METHOD':c['encryption_method'],
                'PROTOCOL_TYPE':'SOCKS5','LISTEN_IP':'127.0.0.1','LISTEN_PORT':local_port,
                'SOCKS5_AUTH':False, 'SOCKS5_PASS':'',
            })
            exe=td/'masterdnsvpn-client'
            go_build(src,'./cmd/client',exe)
            extra={'client_config.toml':config,
                   'client_resolvers.txt':'1.1.1.1:53\n8.8.8.8:53\n'}
            print('NOTE: Master client ZIP includes a confidential symmetric key; use authenticated download only.',flush=True)
        elif engine=='slipstream':
            from . import slipstream_ali
            installed=slipstream_ali.BINARIES['client']['target']
            # Only distribute the exactly pinned, reviewed release. A local
            # binary with the same name is NOT sufficient for client sharing.
            slipstream_ali.check_binary(installed,'client',cli=False)
            slipstream_ali.check_binary(slipstream_ali.BINARIES['server']['target'],'server',cli=False)
            exe=td/'slipstream-rust-client'
            shutil.copy2(installed,exe);exe.chmod(0o755)
            cert=core.ROOT/'keys/slipstream-rust.crt'
            if not cert.is_file():raise RuntimeError('Pinned public TLS certificate missing')
            extra={'slipstream-rust.crt':cert.read_bytes(),
                   'SLIPSTREAM_CLIENT_OPTIONS_FA_EN.md':(pathlib.Path(__file__).resolve().parent.parent/'docs/SLIPSTREAM_CLIENT_OPTIONS_FA_EN.md').read_bytes(),
                   'UPSTREAM-RELEASE.txt':f"{slipstream_ali.REPO} tag={slipstream_ali.TAG}\nclient SHA256={slipstream_ali.BINARIES['client']['sha256']}\nserver SHA256={slipstream_ali.BINARIES['server']['sha256']}\n"}
            commit=slipstream_ali.TAG
        else:raise RuntimeError('Unsupported client builder')
        guide=workflow.build_client_guide(engine,resolver,local_port)
        if not guide['example_command']:raise RuntimeError('Client config is missing public key')
        txt=('DNS Unified Control | Linux amd64 client\n\n'
             +'Domain: '+guide['domain']+'\n'
             +'Command (after extracting the zip):\n'+guide['example_command']+'\n\n'
             +'Verification:\n'+str(guide['verification_command'] or '(manual)')+'\n\n'
             +('NOTE: Native SlipNet includes its own in-process SOCKS5; no gateway is installed.\n' if engine=='noizdns' else 'NOTE: Local port is a TCP forward, not SOCKS5 unless backend explicitly offers SOCKS.\n')
             +'SSH username and authentication are NOT included. Keep private keys confidential.\n'
             + ('CONFIDENTIAL: This ZIP contains the MasterDnsVPN shared encryption secret. Never share it.\n' if engine=='master' else '')
             +'Source: '+guide['docs']+'\n'
             +'Source commit: '+commit+'\n')
        result=jobs.artifact_path(engine);result.parent.mkdir(parents=True,exist_ok=True)
        tempzip=td/'archive.zip'
        with zipfile.ZipFile(tempzip,'w',compression=zipfile.ZIP_DEFLATED) as z:
            spec=zipfile.ZipInfo(exe.name);spec.external_attr=0o100755<<16
            spec.compress_type=zipfile.ZIP_DEFLATED
            z.writestr(spec,exe.read_bytes())
            for name,contents in extra.items():
                if name in ('run-noizdns.sh','run-noizdns-inject-auth.sh'):
                    item=zipfile.ZipInfo(name);item.external_attr=0o100755<<16
                    item.compress_type=zipfile.ZIP_DEFLATED
                    z.writestr(item,contents)
                else:z.writestr(name,contents)
            z.writestr('README.txt',txt)
        # Atomic replace and read-only shared result; never package any .key/.pass.
        os.chmod(tempzip,0o600)
        os.replace(tempzip,result)
        return {'artifact':result.name,'sha256':hashlib.sha256(result.read_bytes()).hexdigest(),
                'source_commit':commit,'message':'Linux amd64 client package ready for secure authenticated download.'}



def build_alternate(engine,resolver='1.1.1.1:53',local_port=2080):
    from .client_catalog import build_settings
    settings=build_settings(resolver,local_port)
    resolver,local_port=settings['resolver'],settings['port']
    """Build an independent client alternative; never rewrite primary artifact."""
    if engine not in jobs.ACTIONS['build-alternate']:raise ValueError('unsupported alternate')
    if platform.machine()!='x86_64': raise RuntimeError('Only Linux x86_64 packages supported')
    from . import slipnet_native
    with tempfile.TemporaryDirectory(prefix='duc-alternate-') as tmp:
        td=pathlib.Path(tmp)
        pk=workflow.public_key(engine)
        if not pk:raise RuntimeError('Server public key unavailable')
        c=core.profiles()[engine]
        if c.get('target')!='127.0.0.1:1080':
            raise RuntimeError('Alternate shared SOCKS client requires Dante backend 127.0.0.1:1080')
        if engine=='noizdns':
            src,commit=source('dnstt')
            exe=td/'dnstt-client'
            go_build(src,'./dnstt-client',exe)
            extra={'server.pub':pk+'\n',
                   'run-client.sh':"#!/usr/bin/env bash\nset -Eeuo pipefail\ncd -- \"$(dirname -- \"${BASH_SOURCE[0]}\")\"\nexec ./dnstt-client -udp \"${DUC_DNS_RESOLVER:-__DEFAULT_RESOLVER__}\" -pubkey-file ./server.pub \""+c['domain']+"\" \"127.0.0.1:${DUC_CLIENT_PORT:-__DEFAULT_PORT__}\"\n",
                   'NOTICE.txt':'Standard DNSTT compatible client for NoizDNS server. This mode does NOT enable NoizDNS Stealth.\n'}
            extra['run-client.sh']=extra['run-client.sh'].replace('__DEFAULT_RESOLVER__',resolver).replace('__DEFAULT_PORT__',str(local_port))
        else:
            raw,commit,sha=slipnet_native.get_release_binary()
            exe=td/'slipnet-linux-amd64';exe.write_bytes(raw);exe.chmod(0o755)
            mode='dnstt' if engine=='dnstt' else 'vaydns'
            options=({'dnstt_compat':c.get('dnstt_compat',False),
                      'record_type':c.get('record_type','txt'),
                      'vay_idle_timeout':c.get('vay_idle_timeout',10),
                      'vay_keepalive':c.get('vay_keepalive',2)} if engine=='vaydns' else None)
            extra={'slipnet-profile.txt':slipnet_native.profile_text(c['domain'],pk,resolver,local_port,stealth=False,
                    tunnel_type=mode,vaydns=options)+'\n',
                   'run-client.sh':slipnet_native.launcher(mode,default_resolver=resolver,default_port=local_port),
                   'UPSTREAM.txt':f'SlipNet {commit} SHA256={sha}\n',
                   'NOTICE.txt':'SlipNet upstream supports this engine. E2E with this DUC server is NOT field-verified; test SOCKS5.\n'}
        extra['README.txt']=(f'DNS Unified Control alternative client for {engine}\n'
           f'Server: {c["domain"]}\nClient: {exe.name}\n'
           f'Run chmod +x ./run-client.sh and ./run-client.sh (resolver={resolver}, port={local_port})\n'
           'Only one client may listen on 127.0.0.1:2080.\n'
           'No keys, Dante password, SSH credentials, or Cloudflare token are distributed.\n'
           'Use curl --socks5-hostname 127.0.0.1:2080 --proxy-user USER:PASS https://api.ipify.org\n')
        path=jobs.alternate_artifact_path(engine);path.parent.mkdir(parents=True,exist_ok=True)
        archive=td/'artifact.zip'
        with zipfile.ZipFile(archive,'w',compression=zipfile.ZIP_DEFLATED) as z:
            for entry in [exe]:
                zi=zipfile.ZipInfo(entry.name);zi.external_attr=0o100755<<16;zi.compress_type=zipfile.ZIP_DEFLATED
                z.writestr(zi,entry.read_bytes())
            for name,contents in extra.items():
                if name=='run-client.sh':
                    zi=zipfile.ZipInfo(name);zi.external_attr=0o100755<<16;zi.compress_type=zipfile.ZIP_DEFLATED
                    z.writestr(zi,contents)
                else:z.writestr(name,contents)
        os.chmod(archive,0o600)
        os.replace(archive,path)
        return {'artifact':path.name,'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
                'source_commit':commit,'message':'Independent alternate client built. DNS engine untouched.'}

def worker(action,engine,jobid):
    if action not in jobs.ACTIONS or engine not in jobs.ACTIONS[action]:return 2
    p=jobs.job_file(action,engine)
    initial=jobs.info(action,engine)
    settings=({'resolver':initial.get('resolver','1.1.1.1:53'),
               'port':initial.get('port',2080)}
              if action in ('build-client','build-alternate') else {})
    def publish(state,message,**extra):
        current=jobs.info(action,engine)
        if current.get('job_id')!=jobid:raise RuntimeError('Job superseded')
        core.atomic_json(p,{'action':action,'engine':engine,'job_id':jobid,'state':state,
                            'message':message,'unit':current.get('unit',''),'updated':time.time(),**settings,**extra})
    try:
        publish('running','Working; the engine is NOT started automatically')
        if action in ('install-dante','setup-dante'):
            from . import dante
            result=dante.install()
        else:
            result=(install_server(engine) if action=='install-server' else
                    build_alternate(engine,**{'resolver':settings['resolver'],'local_port':settings['port']}) if action=='build-alternate' else build_client(engine,**{'resolver':settings['resolver'],'local_port':settings['port']}))
        publish('succeeded',package_schema='0.9.7',**result)
        print('SUCCEEDED:',engine,action,flush=True)
        return 0
    except Exception as e:
        publish('failed',str(e)[:300])
        print('FAILED:',type(e).__name__,str(e)[:300],flush=True)
        return 1

if __name__=='__main__':
    sys.exit(worker(*sys.argv[1:]) if len(sys.argv)==4 else 2)
