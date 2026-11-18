"""Regression checks for real client settings through job, worker and ZIP."""
import io
import zipfile
import subprocess
import pytest
from fastapi.testclient import TestClient
from duc import client_catalog, core, jobs, worker, slipnet_native


def test_build_settings_validation():
    assert client_catalog.build_settings('8.8.8.8:53',2180) == {'resolver':'8.8.8.8:53','port':2180}
    for r in ('invalid','127.0.0.1:999999','1.1.1.999:53','1.1.1.1:0','8.8.8.8:53;whoami'):
        with pytest.raises(ValueError):client_catalog.build_settings(r,2080)
    for port in (0,80,65536,True,'2080'):
        with pytest.raises(ValueError):client_catalog.build_settings('1.1.1.1:53',port)


def test_noizdns_profile_and_launcher_defaults():
    f = slipnet_native.profile_fields('n.example.com','a'*64,'8.8.8.8:53',2233)
    assert f[4]=='8.8.8.8:53:0' and f[8]=='2233' and f[38]=='1'
    for script in (slipnet_native.launcher(default_resolver='8.8.8.8:53',default_port=2233),
                   slipnet_native.launcher('vaydns',default_resolver='8.8.8.8:53',default_port=2233),
                   slipnet_native.auth_launcher('8.8.8.8:53',2233)):
        assert '${DUC_DNS_RESOLVER:-8.8.8.8:53}' in script
        assert '${DUC_CLIENT_PORT:-2233}' in script
        assert subprocess.run(['bash','-n'],input=script,text=True).returncode == 0


def test_build_client_settings_are_used_in_zip(monkeypatch,tmp_path):
    monkeypatch.setattr(core,'ROOT',tmp_path/'etc')
    monkeypatch.setattr(core,'STATE',tmp_path/'state')
    keys=core.ROOT/'keys';keys.mkdir(parents=True)
    (keys/'noizdns.pub').write_text('a'*64)
    c={e:{'domain':f'{e}.example.com','target':'127.0.0.1:1080'} for e in core.ENGINES}
    monkeypatch.setattr(core,'profiles',lambda:c)
    monkeypatch.setattr(slipnet_native,'get_release_binary',lambda:(b'\x7fELF'+b'A'*2000,'v2.5.3','f'*64))
    r=worker.build_client('noizdns','8.8.8.8:53',2233)
    zpath=jobs.artifact_path('noizdns')
    assert r['artifact']==zpath.name
    with zipfile.ZipFile(zpath) as z:
        profile=z.read('slipnet-profile.txt').decode().split('|')
        script=z.read('run-noizdns.sh').decode()
        assert profile[4]=='8.8.8.8:53:0' and profile[8]=='2233'
        assert '${DUC_DNS_RESOLVER:-8.8.8.8:53}' in script
        assert '${DUC_CLIENT_PORT:-2233}' in script
        assert 'slipnet-linux-amd64' in z.namelist()


def test_agent_settings_route_wired(monkeypatch):
    from duc.agent import app
    recorded={}
    def fake_start(action,engine,settings):
        recorded.update(action=action,engine=engine,settings=settings)
        return {'state':'queued'}
    monkeypatch.setattr(jobs,'initiate',fake_start)
    client=TestClient(app)
    assert client.post('/workflow/jobs/build-client/noizdns',json={'confirm':'build-client:noizdns','resolver':'8.8.8.8:53','port':2222}).status_code==200
    assert recorded['settings']=={'resolver':'8.8.8.8:53','port':2222}
    assert client.post('/workflow/jobs/setup-dante/dante',json={'confirm':'setup-dante:dante','resolver':'8.8.8.8:53'}).status_code==422


def test_older_alt_zip_is_stale(monkeypatch,tmp_path):
    monkeypatch.setattr(core,'STATE',tmp_path)
    path=jobs.job_file('build-alternate','dnstt')
    core.atomic_json(path,{'action':'build-alternate','engine':'dnstt','state':'succeeded','artifact':'dnstt-alternate-linux-amd64.zip','package_schema':'0.9.6'})
    assert jobs.info('build-alternate','dnstt')['state']=='stale'
    core.atomic_json(path,{'action':'build-alternate','engine':'dnstt','state':'succeeded','artifact':'dnstt-alternate-linux-amd64.zip','package_schema':'0.9.7','resolver':'8.8.8.8:53','port':2222})
    assert jobs.info('build-alternate','dnstt')['state']=='succeeded'


def test_alternate_zip_preserves_selected_settings(monkeypatch,tmp_path):
    monkeypatch.setattr(core,'ROOT',tmp_path/'etc')
    monkeypatch.setattr(core,'STATE',tmp_path/'state')
    keys=core.ROOT/'keys';keys.mkdir(parents=True)
    for engine in ('noizdns','dnstt','vaydns'):(keys/f'{engine}.pub').write_text('a'*64)
    c={e:{'domain':f'{e}.example.com','target':'127.0.0.1:1080','record_type':'txt'} for e in core.ENGINES}
    monkeypatch.setattr(core,'profiles',lambda:c)
    monkeypatch.setattr(worker,'source',lambda engine:(tmp_path,'pin'))
    monkeypatch.setattr(worker,'go_build',lambda src,subdir,dest:dest.write_bytes(b'\x7fELF'+b'X'*2000))
    monkeypatch.setattr(slipnet_native,'get_release_binary',lambda:(b'\x7fELF'+b'A'*2000,'v2.5.3','f'*64))
    for engine in ('noizdns','dnstt','vaydns'):
        worker.build_alternate(engine,'8.8.8.8:53',2233)
        with zipfile.ZipFile(jobs.alternate_artifact_path(engine)) as z:
            script=z.read('run-client.sh').decode()
            assert '${DUC_DNS_RESOLVER:-8.8.8.8:53}' in script
            assert '${DUC_CLIENT_PORT:-2233}' in script
            assert subprocess.run(['bash','-n'],input=script,text=True).returncode==0
            if engine!='noizdns':
                profile=z.read('slipnet-profile.txt').decode().split('|')
                assert profile[4]=='8.8.8.8:53:0' and profile[8]=='2233'


def test_job_request_persists_settings(monkeypatch,tmp_path):
    import contextlib
    from types import SimpleNamespace
    monkeypatch.setattr(core,'STATE',tmp_path)
    monkeypatch.setattr(core,'switch_lock',contextlib.nullcontext)
    def fake_run(args,**kw):return SimpleNamespace(returncode=0,stderr='',stdout='')
    monkeypatch.setattr(jobs.subprocess,'run',fake_run)
    state=jobs.initiate('build-alternate','dnstt',{'resolver':'8.8.8.8:53','port':2233})
    assert state['state']=='queued' and state['resolver']=='8.8.8.8:53' and state['port']==2233
    with pytest.raises(ValueError):jobs.initiate('setup-dante','dante',{'resolver':'8.8.8.8:53'})
