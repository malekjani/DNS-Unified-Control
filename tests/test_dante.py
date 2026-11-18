import base64
import json
import pathlib
import pytest
from duc import dante, core, jobs


def test_dante_config_auth_and_loopback():
    c=dante.configuration('eth0')
    assert 'internal: 127.0.0.1 port = 1080' in c
    assert 'external: eth0' in c
    assert 'socksmethod: username' in c
    assert 'command: connect' in c
    assert 'protocol: tcp' in c
    assert '127.0.0.0/8' in c
    assert '169.254.0.0/16' in c
    assert '0.0.0.0 port = 1080' not in c
    assert '5300' not in c and 'port = 53' not in c


def test_dante_config_bad_interface():
    with pytest.raises(ValueError):dante.configuration('eth0\ninternal: 0.0.0.0')


def test_dante_job_is_fixed_action():
    assert jobs.ACTIONS['install-dante']==('slipstream',)
    assert 'dante' not in core.ENGINES
    assert 'dns-unified-dante.service' not in core.UNITS.values()


def test_dante_credentials_root_private_only(monkeypatch,tmp_path):
    credentials={'user':'duc-socks','password':'secret-password-for-test-only'}
    path=tmp_path/'dante-auth.json'
    path.write_text(json.dumps(credentials));path.chmod(0o600)
    monkeypatch.setattr(dante,'AUTH_FILE',path)
    uri=dante.credentials()
    assert uri.startswith('socks://') and uri.endswith('@127.0.0.1:2080#SlipStream-Dante')
    encoded=uri.split('socks://',1)[1].split('@',1)[0]
    assert base64.b64decode(encoded)==b'duc-socks:secret-password-for-test-only'
    path.chmod(0o644)
    with pytest.raises(RuntimeError):dante.credentials()


def test_dante_activation_checks_health(monkeypatch):
    monkeypatch.setattr(dante,'status',lambda:{'ready':False})
    with pytest.raises(ValueError,match='not healthy'):
        dante.activate('socks5')


def test_dante_activation_does_not_switch_other_engines(monkeypatch):
    called=[]
    monkeypatch.setattr(dante,'status',lambda:{'ready':True})
    monkeypatch.setattr(core,'profiles',lambda:{'slipstream':{'target':'127.0.0.1:22'}})
    monkeypatch.setattr(core,'list_active',lambda:['iodine'])
    monkeypatch.setattr(core,'update_profile',lambda eng,data:called.append((eng,data)))
    monkeypatch.setattr(core,'switch',lambda *args,**kw: pytest.fail('must not switch active iodine'))
    result=dante.activate('socks5')
    assert result['stage']=='saved-for-next-slipstream-start'
    assert called==[('slipstream',{'target':'127.0.0.1:1080'})]


def test_dante_activation_uses_exclusive_switch(monkeypatch):
    called=[]
    monkeypatch.setattr(dante,'status',lambda:{'ready':True})
    monkeypatch.setattr(core,'profiles',lambda:{'slipstream':{'target':'127.0.0.1:22'}})
    monkeypatch.setattr(core,'list_active',lambda:['slipstream'])
    monkeypatch.setattr(core,'update_profile',lambda eng,data:called.append(('profile',eng,data)))
    monkeypatch.setattr(core,'switch',lambda *args,**kw:called.append(('switch',args,kw)) or {'ok':True})
    result=dante.activate('socks5')
    assert result['stage']=='slipstream-restarted'
    assert ('switch',('slipstream',),{'restart':True}) in called


def test_dante_service_is_not_distro_service():
    assert dante.UNIT=='dns-unified-dante.service'
    assert '/etc/dns-unified/danted.conf' in dante.SYSTEMD
    assert 'ExecStart=/usr/sbin/danted -f' in dante.SYSTEMD


def test_dante_auth_does_not_leak_via_status(monkeypatch):
    monkeypatch.setattr(dante,'authenticated_greeting',lambda:True)
    monkeypatch.setattr(dante,'call',lambda *a,**kw:type('Resp',(),{'returncode':0})())
    monkeypatch.setattr(core,'list_active',lambda:['slipstream'])
    monkeypatch.setattr(core,'profiles',lambda:{'slipstream':{'target':dante.SOCKS_TARGET}})
    obj=dante.status()
    assert obj['profile_mode']=='SOCKS5'
    assert obj['ready']
    assert 'password' not in json.dumps(obj).lower()
