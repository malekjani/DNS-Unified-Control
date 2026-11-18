"""v0.9.6 client choice, TUI registry contract, artifacts, and UI separation."""
import io
import pathlib
import subprocess
import zipfile
import pytest
from fastapi.testclient import TestClient
from duc import core, jobs, worker, client_catalog, slipnet_native


def test_catalog_is_pure_and_machine_readable():
    for engine in core.ENGINES:
        item=client_catalog.options(engine)
        assert item['engine']==engine and item['exclusive_dns']
        assert item['default']==item['choices'][0]['id']
        assert all(x['kind'] in ('native','alternate') for x in item['choices'])
    assert [x['id'] for x in client_catalog.options('noizdns')['choices']]==['slipnet','dnstt']
    assert [x['id'] for x in client_catalog.options('dnstt')['choices']]==['native','slipnet']
    assert [x['id'] for x in client_catalog.options('vaydns')['choices']]==['native','slipnet']
    assert not any(x['id']=='slipnet' for x in client_catalog.options('slipstream')['choices'])
    assert 'password' not in repr(client_catalog.options('noizdns')).lower()
    with pytest.raises(ValueError):client_catalog.options('not-an-engine')


def test_slipnet_mode_and_launcher():
    domain='d.example.com';key='a'*64
    for typ in ('dnstt','vaydns','sayedns'):
        f=slipnet_native.profile_fields(domain,key,stealth=typ=='sayedns',tunnel_type=typ,
                                          vaydns={'record_type':'txt','dnstt_compat':False})
        assert f[1]==typ and f[11]==key
        if typ=='vaydns':assert f[42]=='txt' and f[49]=='2'
        launcher=slipnet_native.launcher(typ)
        assert '--dns "$RESOLVER"' in launcher and '--direct' not in launcher
        assert subprocess.run(['bash','-n'],input=launcher,text=True).returncode==0
    with pytest.raises(ValueError):slipnet_native.profile_fields(domain,key,stealth=True,tunnel_type='dnstt')
    assert subprocess.run(['bash','-n'],input=slipnet_native.auth_launcher(),text=True).returncode==0


def test_alternate_jobs_and_zip_isolation(monkeypatch,tmp_path):
    monkeypatch.setattr(core,'ROOT',tmp_path/'etc')
    monkeypatch.setattr(core,'STATE',tmp_path/'state')
    (core.ROOT/'keys').mkdir(parents=True)
    for eng in ('noizdns','dnstt','vaydns'):(core.ROOT/'keys'/f'{eng}.pub').write_text('e'*64)
    (core.ROOT/'keys'/'noizdns.key').write_text('SECRET_KEY_NEVER_EXPOSED')
    profiles={e:{'domain':f'{e}.example.com','target':'127.0.0.1:1080',
                'record_type':'txt','dnstt_compat':False} for e in core.ENGINES}
    monkeypatch.setattr(core,'profiles',lambda: profiles)
    monkeypatch.setattr(worker,'source',lambda engine:(tmp_path, 'commit-reviewed'))
    def fake_go(src,subdir,dest):dest.write_bytes(b'\x7fELF'+b'0'*2000)
    monkeypatch.setattr(worker,'go_build',fake_go)
    monkeypatch.setattr(slipnet_native,'get_release_binary',lambda:(b'\x7fELF'+b'1'*2000,'v2.5.3','f'*64))
    for eng in ('noizdns','dnstt','vaydns'):
        result=worker.build_alternate(eng)
        target=jobs.alternate_artifact_path(eng)
        assert target.name==result['artifact'] and target.is_file()
        assert target!=jobs.artifact_path(eng)
        assert b'SECRET_KEY_NEVER_EXPOSED' not in target.read_bytes()
        with zipfile.ZipFile(target) as z:
            names=z.namelist()
            assert 'run-client.sh' in names
            assert subprocess.run(['bash','-n'],input=z.read('run-client.sh'),capture_output=True).returncode==0
            if eng=='noizdns':
                assert 'dnstt-client' in names and 'server.pub' in names
                assert 'NoizDNS Stealth' not in z.read('README.txt').decode()
            else:
                f=z.read('slipnet-profile.txt').decode().split('|')
                assert f[1]==eng and f[38]=='0'


def test_client_routes_agent_read_only():
    from duc.agent import app
    cli=TestClient(app)
    assert cli.get('/workflow/client/options/noizdns').json()['default']=='slipnet'
    assert cli.get('/workflow/client/options/none').status_code==404
    assert cli.get('/workflow/client/alternate-download/soar').status_code==404


def test_web_navigation_separation():
    root=pathlib.Path(__file__).resolve().parents[1]
    html=(root/'web/index.html').read_text()
    js=(root/'web/app.js').read_text()
    for t in ('workflow','dante','setup'):
        assert f'data-tab="{t}"' in html and f'id="{t}"' in html
    assert 'async function loadDante()' in js and 'async function loadSetup()' in js
    assert '/api/workflow/client/options/' in js
    assert '/api/workflow/jobs/build-alternate/' in js


def test_noizdns_legacy_client_marked_stale(monkeypatch,tmp_path):
    import time
    monkeypatch.setattr(core,'STATE',tmp_path)
    infofile=jobs.job_file('build-client','noizdns')
    core.atomic_json(infofile,{'action':'build-client','engine':'noizdns','state':'succeeded',
                               'artifact':'noizdns-linux-amd64.zip','updated':time.time()})
    old=jobs.info('build-client','noizdns')
    assert old['state']=='stale' and 'Rebuild' in old['message']
    core.atomic_json(infofile,{'action':'build-client','engine':'noizdns','state':'succeeded',
                               'artifact':'noizdns-linux-amd64.zip','updated':time.time(),
                               'package_schema':'0.9.7'})
    assert jobs.info('build-client','noizdns')['state']=='succeeded'


def test_dante_job_is_its_own_service(monkeypatch,tmp_path):
    monkeypatch.setattr(core,'STATE',tmp_path)
    assert jobs.job_file('setup-dante','dante').name=='setup-dante-dante.json'
    assert jobs.job_file('install-dante','slipstream').name=='install-dante-slipstream.json'
    with pytest.raises(ValueError):jobs.job_file('setup-dante','dnstt')
    from duc import worker
    assert 'setup-dante' in jobs.ACTIONS and jobs.ACTIONS['setup-dante']==('dante',)
