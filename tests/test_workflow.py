import hashlib
import io
import json
import pathlib
import zipfile
import pytest
from duc import core,jobs,workflow,worker


def test_client_guide_is_validated_and_has_no_secret(tmp_path,monkeypatch):
    monkeypatch.setattr(core,'ROOT',tmp_path)
    (tmp_path/'keys').mkdir()
    (tmp_path/'keys/dnstt.pub').write_text('a'*64)
    (tmp_path/'keys/dnstt.key').write_text('SUPERPRIVATE')
    guide=workflow.build_client_guide('dnstt',resolver='8.8.8.8:53',local_port=2222)
    assert '8.8.8.8:53' in guide['example_command']
    assert "'a" not in guide['example_command']
    assert '-pubkey-file ./server.pub' in guide['example_command']
    assert guide['public_key'] == 'a'*64
    assert 'SUPERPRIVATE' not in json.dumps(guide)
    assert 'curl' in guide['verification_command']
    with pytest.raises(ValueError): workflow.build_client_guide('dnstt','1.1.1.1:53; rm -rf /')
    with pytest.raises(ValueError): workflow.build_client_guide('dnstt','999.999.999.999:53')
    with pytest.raises(ValueError): workflow.build_client_guide('dnstt',local_port=22)
    with pytest.raises(ValueError): workflow.build_client_guide('bad')


def test_all_nine_methods_have_guides(tmp_path,monkeypatch):
    monkeypatch.setattr(core,'ROOT',tmp_path)
    for engine in core.ENGINES:
        guide=workflow.build_client_guide(engine)
        assert guide['domain'].startswith(core.LABELS[engine]+'.')
        assert guide['docs'].startswith('https://')
        assert guide['steps']
    for engine in ('xdns','soar','noizdns'):
        assert workflow.build_client_guide(engine)['example_command'] is None


def test_dnstt_client_zip_public_only(tmp_path,monkeypatch):
    monkeypatch.setattr(core,'ROOT',tmp_path/'etc')
    monkeypatch.setattr(core,'STATE',tmp_path/'state')
    (core.ROOT/'keys').mkdir(parents=True)
    (core.ROOT/'keys/dnstt.pub').write_text('f'*64+'\n')
    (core.ROOT/'keys/dnstt.key').write_text('NEVERPACKTHIS')
    monkeypatch.setattr(worker,'source',lambda e:(tmp_path,'0123456789abcdef'))
    def fakego(src,subdir,dest):
        dest.write_bytes(b'\x7fELF'+b'\x00'*100010)
        dest.chmod(0o755)
    monkeypatch.setattr(worker,'go_build',fakego)
    result=worker.build_client('dnstt')
    archive=jobs.artifact_path('dnstt')
    assert archive.is_file()
    assert hashlib.sha256(archive.read_bytes()).hexdigest()==result['sha256']
    with zipfile.ZipFile(archive) as z:
        assert set(z.namelist())=={'dnstt-client','README.txt','server.pub'}
        assert z.read('server.pub').strip()==b'f'*64
        assert b'NEVERPACKTHIS' not in archive.read_bytes()
        assert b'8.8.8.8' not in z.read('README.txt') # default uses 1.1.1.1


def test_safe_job_initiation(tmp_path,monkeypatch):
    monkeypatch.setattr(core,'STATE',tmp_path)
    monkeypatch.setattr(core,'is_active',lambda e:False)
    calls=[]
    class R:
        returncode=0
        stderr=''
    monkeypatch.setattr(jobs.subprocess,'run',lambda args,**kw:calls.append(args) or R())
    r=jobs.initiate('build-client','dnstt')
    assert r['state']=='queued'
    assert calls and calls[0][0]=='systemd-run'
    assert calls[0][-3:-1]==['build-client','dnstt']
    with pytest.raises(ValueError):jobs.initiate('install-server','xdns')
    with pytest.raises(ValueError):jobs.initiate('build-client','../../etc/passwd')
    with pytest.raises(ValueError):jobs.initiate('build-client','dnstt')


def test_installer_patches_mfa_and_has_safe_upgrade():
    base=pathlib.Path(__file__).resolve().parent.parent
    installer=(base/'install.sh').read_text()
    assert 'install -d -m 0710 -o root -g dns-unified /var/lib/dns-unified' in installer
    assert 'DUC_SKIP_WIZARD' in installer
    upgrade=(base/'upgrade.sh').read_text()
    assert 'DUC_SKIP_WIZARD=1' in upgrade and 'DUC_INSTALL_ENGINES=0' in upgrade
    html=(base/'web/index.html').read_text()
    assert 'data-tab="workflow"' in html
    assert 'id="workflow"' in html


def test_public_guide_bundle_all_nine_never_contains_private(tmp_path,monkeypatch):
    monkeypatch.setattr(core,'ROOT',tmp_path)
    (tmp_path/'keys').mkdir()
    (tmp_path/'keys/dnstt.key').write_text('TEST_PRIVATE_KEY_NOT_TO_DISTRIBUTE')
    (tmp_path/'keys/dnstt.pub').write_text('b'*64)
    (tmp_path/'keys/slipstream-rust.crt').write_text('CERTIFICATE_ONLY')
    (tmp_path/'keys/slipstream-rust.key').write_text('SHOULD_NOT_DISTRIBUTE')
    for e in core.ENGINES:
        output=workflow.create_public_guide_bundle(e)
        with zipfile.ZipFile(io.BytesIO(output)) as z:
            assert 'README.txt' in z.namelist()
            if e=='noizdns':
                assert 'client-profile.json' not in z.namelist()
                assert 'UPSTREAM.txt' in z.namelist()
            else:
                assert 'client-profile.json' in z.namelist()
            assert all(not name.endswith(('.key','.pass')) for name in z.namelist())
            assert b'TEST_PRIVATE_KEY_NOT_TO_DISTRIBUTE' not in output
            assert b'SHOULD_NOT_DISTRIBUTE' not in output
            if e=='dnstt': assert b'b'*64 in z.read('server.pub')


def test_wrong_conflict_never_overwrites_unmanaged_cloudflare_records():
    from duc import cloudflare_dns
    class Mock:
        def __init__(self):self.writes=[]
        def zone(self,domain):return 'foo'
        def records(self,zone,name):
            if name.startswith('ns.'):
                return [{'type':'A','name':name,'content':'203.0.113.1','proxied':False,'comment':'PERSONAL'}]
            return []
        def call(self,*a):self.writes.append(a)
    client=Mock()
    with pytest.raises(cloudflare_dns.ProvisionError):
        cloudflare_dns.apply_all(client,'m2m.diy','188.132.174.249')
    assert not client.writes


def test_worker_persists_job_without_rerunning_installer(tmp_path,monkeypatch):
    monkeypatch.setattr(core,'STATE',tmp_path)
    job=jobs.job_file('install-server','dnstt')
    core.atomic_json(job,{'engine':'dnstt','action':'install-server','state':'queued',
                          'job_id':'unit-test-id','unit':'duc-job-unit-test','updated':1})
    monkeypatch.setattr(worker,'install_server',lambda e:{'message':'Finished from test','source_commit':'abc123'})
    rc=worker.worker('install-server','dnstt','unit-test-id')
    assert rc==0
    result=jobs.info('install-server','dnstt')
    assert result['state']=='succeeded'
    assert result['source_commit']=='abc123'
    assert result['unit']=='duc-job-unit-test'


def test_go_builder_has_explicit_cache_without_home(tmp_path, monkeypatch):
    """systemd-run's minimal environment must not break Go module builds."""
    import os
    monkeypatch.setattr(worker, 'GO_CACHE_ROOT', tmp_path/'go-cache')
    monkeypatch.setattr(worker.shutil, 'which', lambda cmd: '/usr/bin/go' if cmd=='go' else None)
    monkeypatch.delenv('HOME', raising=False)
    monkeypatch.delenv('GOPATH', raising=False)
    monkeypatch.delenv('GOMODCACHE', raising=False)
    monkeypatch.delenv('GOCACHE', raising=False)
    calls=[]
    def fake_run(args, cwd=None, timeout=900, env=None):
        calls.append((args, cwd, env))
        pathlib.Path(args[args.index('-o')+1]).write_bytes(b'\x7fELF'+b'\x00'*100010)
    monkeypatch.setattr(worker, 'run', fake_run)
    out=tmp_path/'dnstt-client'
    worker.go_build(tmp_path,'./dnstt-client',out)
    assert out.is_file()
    assert out.stat().st_mode & 0o111
    args,cwd,env=calls[0]
    assert args[:2]==['go','build']
    assert 'HOME' not in env
    assert pathlib.Path(env['GOPATH']).is_dir()
    assert pathlib.Path(env['GOMODCACHE']).is_dir()
    assert pathlib.Path(env['GOCACHE']).is_dir()
    assert pathlib.Path(env['GOPATH'])==tmp_path/'go-cache'
    assert env['GOMAXPROCS']=='1' and env['CGO_ENABLED']=='0'
    assert env['GOFLAGS']=='-p=1'
