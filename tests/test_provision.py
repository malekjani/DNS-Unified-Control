import json
import os
import pathlib
import zipfile

from duc import core, provision, worker, jobs


def test_registry_has_all_nine_engines():
    assert set(provision.STRATEGIES) == set(core.ENGINES)
    assert provision.STRATEGIES['slipstream'].heavyweight
    assert provision.STRATEGIES['xdns'].kind == 'review'
    assert provision.STRATEGIES['master'].kind == 'go'


def test_secret_preserves_existing_and_repairs_permissions(tmp_path):
    p=tmp_path/'keys/master.key'
    assert provision.create_secret(p, 64) is True
    first=p.read_bytes()
    assert len(first.strip())==64
    p.chmod(0o666)
    assert provision.create_secret(p, 64) is False
    assert p.read_bytes()==first
    assert p.stat().st_mode & 0o077 == 0


def test_master_template_is_idempotent(tmp_path,monkeypatch):
    monkeypatch.setattr(core,'ROOT',tmp_path/'etc')
    sample=tmp_path/'source/server_config.toml.simple'
    sample.parent.mkdir()
    sample.write_text('DOMAIN = ["v.domain.com"]\n'
                      'PROTOCOL_TYPE = "SOCKS5"\n'
                      'USE_EXTERNAL_SOCKS5 = false\n'
                      'SOCKS5_AUTH = false\n'
                      'SOCKS5_PASS = "123456"\n'
                      'UDP_HOST = ""\nUDP_PORT = 53\n')
    provision.configure_master(sample.parent)
    config=core.ROOT/'engines/master/base.toml'
    first=config.read_bytes()
    assert b'SOCKS5_PASS = ""' in first
    secret=core.ROOT/'keys/master.key'
    first_secret=secret.read_bytes()
    provision.configure_master(sample.parent)
    assert config.read_bytes()==first
    assert secret.read_bytes()==first_secret
    assert config.stat().st_mode & 0o077 == 0


def test_batch_preserves_active_engine_and_persists_after_each(tmp_path,monkeypatch):
    monkeypatch.setattr(core,'STATE',tmp_path/'state')
    monkeypatch.setattr(provision,'REPORT',core.STATE/'provision-report.json')
    monkeypatch.setattr(provision,'LOCK',core.STATE/'provision.lock')
    monkeypatch.setattr(provision.os,'geteuid',lambda:0)
    monkeypatch.setattr(core,'list_active',lambda:['dnstt'])
    monkeypatch.setattr(core,'is_active',lambda engine:engine=='dnstt')
    monkeypatch.setattr(provision,'readiness',lambda e:{'ready':False,'issues':['missing'], 'binary':''})
    monkeypatch.setattr(provision.shutil,'which',lambda e:None)
    called=[]
    def fakeinstall(engine):
        called.append(engine)
        return {'source_commit':'deadbeef'}
    monkeypatch.setattr(provision,'install_go',fakeinstall)
    result=provision.execute(only=('dnstt','master'),skip_toolchain=True)
    assert called==['master']
    assert result['engines']['dnstt']['state']=='preserved-running'
    assert result['engines']['master']['state']=='failed' # template not available in isolated test
    assert result['active_after']==['dnstt']
    report=json.loads(provision.REPORT.read_text())
    assert report['completed'] is not None
    assert report['engines']['dnstt']['state']=='preserved-running'


def test_dry_run_never_calls_installer(monkeypatch):
    monkeypatch.setattr(core,'is_active',lambda engine:False)
    monkeypatch.setattr(provision,'readiness',lambda engine:{'ready':False,'issues':[],'binary':''})
    monkeypatch.setattr(provision.shutil,'which',lambda e:None)
    monkeypatch.setattr(provision,'install_go',lambda e: (_ for _ in ()).throw(AssertionError('unexpected install')))
    r=provision.execute(only=('master','xdns'),dry_run=True)
    assert r['engines']['master']['state']=='would-install'
    assert r['engines']['xdns']['state']=='requires-review'


def test_master_client_bundle_contains_expected_config_secret(tmp_path,monkeypatch):
    source=tmp_path/'source'
    source.mkdir()
    (source/'client_config.toml.simple').write_text(
        'DOMAINS = ["v.domain.com"]\nENCRYPTION_KEY = ""\n'
        'DATA_ENCRYPTION_METHOD = 1\nPROTOCOL_TYPE = "SOCKS5"\n'
        'LISTEN_IP = "127.0.0.1"\nLISTEN_PORT = 18000\n'
        'SOCKS5_AUTH = false\nSOCKS5_PASS = "master_dns_vpn"\n'
    )
    monkeypatch.setattr(worker,'source',lambda engine:(source,'cafe0dee'))
    def mockgo(src,subdir,dest):
        assert subdir=='./cmd/client'
        dest.write_bytes(b'\x7fELF'+b'X'*100010)
    monkeypatch.setattr(worker,'go_build',mockgo)
    monkeypatch.setattr(core,'ROOT',tmp_path/'etc')
    monkeypatch.setattr(core,'STATE',tmp_path/'state')
    (core.ROOT/'keys').mkdir(parents=True)
    (core.ROOT/'keys/master.key').write_text('b'*64+'\n')
    base=core.profiles()
    base['master']['domain']='m.m2m.diy'
    monkeypatch.setattr(core,'profiles',lambda:base)
    result=worker.build_client('master')
    with zipfile.ZipFile(jobs.artifact_path('master')) as bundle:
        assert {'masterdnsvpn-client','client_config.toml','client_resolvers.txt','README.txt'}==set(bundle.namelist())
        content=bundle.read('client_config.toml')
        assert b'm.m2m.diy' in content
        assert b'b'*64 in content
        assert b'DATA_ENCRYPTION_METHOD = 2' in content
        assert b'LISTEN_PORT = 2080' in content
        assert b'CONFIDENTIAL' in bundle.read('README.txt')
    assert jobs.artifact_path('master').stat().st_mode & 0o077 == 0
    assert result['source_commit']=='cafe0dee'


def test_exclusive_switch_refuses_during_provision(tmp_path,monkeypatch):
    import fcntl
    monkeypatch.setattr(core,'STATE',tmp_path)
    monkeypatch.setattr(core,'list_active',lambda: ['dnstt'])
    monkeypatch.setattr(core,'check_ready',lambda engine:{'ready':True,'issues':[]})
    calls=[]
    monkeypatch.setattr(core,'run',lambda args,timeout=12: calls.append(args) or type('R',(),{'returncode':0,'stderr':''})())
    p=tmp_path/'provision.lock'
    with p.open('a+') as hold:
        fcntl.flock(hold.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        result=core.switch('master')
        assert result['stage']=='provisioning'
        assert result['before']==['dnstt']
        assert not any('stop' in cmd for cmd in calls)
