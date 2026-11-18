import pathlib
import pytest
from duc import core, runner

@pytest.fixture
def tempstore(tmp_path,monkeypatch):
    monkeypatch.setattr(core,'ROOT',tmp_path/'config')
    monkeypatch.setattr(core,'STATE',tmp_path/'state')
    monkeypatch.setattr(runner,'ROOT',tmp_path/'config')
    return tmp_path

def test_validation_rejects_shell_and_unknown_values():
    assert core.validate('domain','V.EXAMPLE.COM.')=='v.example.com'
    for bad in ['a;rm -rf /','bad_domain!','localhost','foo.com\n']:
        with pytest.raises(ValueError):core.validate('domain',bad)
    for bad in ['0.0.0.0:22','127.0.0.1:0','127.0.0.1:foo']:
        with pytest.raises(ValueError):core.validate('target',bad)
    with pytest.raises(ValueError):core.validate('arq_window','500')

def test_profile_allowlist(tempstore):
    result=core.update_profile('master',{'domain':'m.example.net','arq_window':500})
    assert result['domain']=='m.example.net'
    assert core.profiles()['master']['arq_window']==500
    with pytest.raises(ValueError):core.update_profile('master',{'custom_cmd':'rm -rf /'})
    assert core.profiles()['master']['arq_window']==500

class FakeManager:
    def __init__(self,initial=()): self.active=set(initial);self.fail=None;self.commands=[]
    def run(self,cmd,timeout=10):
        self.commands.append(cmd);unit=cmd[-1].split('@')[-1].split('.')[0]
        from types import SimpleNamespace
        if len(cmd)>=2 and cmd[0]=='systemctl' and cmd[1]=='stop': self.active.discard(unit)
        if len(cmd)>=2 and cmd[0]=='systemctl' and cmd[1]=='start':
            if unit==self.fail: return SimpleNamespace(returncode=1,stderr='unit failed',stdout='')
            self.active.add(unit)
        return SimpleNamespace(returncode=0,stderr='',stdout='')

def test_exclusive_switch(tempstore,monkeypatch):
    f=FakeManager(['dnstt'])
    monkeypatch.setattr(core,'list_active',lambda:list(f.active))
    monkeypatch.setattr(core,'is_active',lambda e:e in f.active)
    monkeypatch.setattr(core,'run',f.run)
    monkeypatch.setattr(core,'port_53_busy',lambda port:[])
    monkeypatch.setattr(core,'check_ready',lambda e,conf=None:{'ready':True,'issues':[]})
    monkeypatch.setattr(core,'await_active',lambda e,seconds=6:e in f.active)
    result=core.switch('master')
    assert result['ok'] is True
    assert f.active=={'master'}
    assert ['systemctl','stop',core.UNITS['dnstt']] in f.commands
    assert ['systemctl','start',core.UNITS['master']] in f.commands

def test_rollback(tempstore,monkeypatch):
    f=FakeManager(['dnstt']);f.fail='master'
    monkeypatch.setattr(core,'list_active',lambda:list(f.active))
    monkeypatch.setattr(core,'is_active',lambda e:e in f.active)
    monkeypatch.setattr(core,'run',f.run)
    monkeypatch.setattr(core,'port_53_busy',lambda port:[])
    monkeypatch.setattr(core,'check_ready',lambda e,conf=None:{'ready':True,'issues':[]})
    monkeypatch.setattr(core,'await_active',lambda e,seconds=6:e in f.active)
    result=core.switch('master')
    assert not result['ok'] and result['stage']=='rollback'
    assert f.active=={'dnstt'}

def test_conflict_prevents_new_service(tempstore,monkeypatch):
    f=FakeManager([])
    monkeypatch.setattr(core,'list_active',lambda:list(f.active))
    monkeypatch.setattr(core,'is_active',lambda e:e in f.active)
    monkeypatch.setattr(core,'run',f.run)
    monkeypatch.setattr(core,'port_53_busy',lambda port:['0.0.0.0:53'])
    monkeypatch.setattr(core,'check_ready',lambda e,conf=None:{'ready':True,'issues':[]})
    result=core.switch('master')
    assert not result['ok'] and 'occupied' in result['error']
    assert not any(c[1]=='start' for c in f.commands)

def test_master_config_render(tempstore,monkeypatch):
    base=core.ROOT/'engines/master/base.toml';base.parent.mkdir(parents=True)
    base.write_text('DOMAIN = ["v.old.com"]\nUDP_PORT = 53\nUDP_HOST = ""\nARQ_WINDOW_SIZE = 1000\nLOG_LEVEL = "INFO"\nDATA_ENCRYPTION_METHOD = 1\nENCRYPTION_KEY_FILE = "key"\n')
    monkeypatch.setattr(runner.shutil,'which',lambda x:'/usr/local/bin/'+x)
    c=dict(core.DEFAULTS['master']);c.update({'domain':'v.myname.net','arq_window':2000})
    argv=runner.cmd_for('master',c)
    assert argv[1]=='-config'
    effective=(core.ROOT/'engines/master/server_config.toml').read_text()
    assert 'ARQ_WINDOW_SIZE = 2000' in effective
    assert 'DOMAIN = ["v.myname.net"]' in effective


def test_dns_cli_argv(tempstore,monkeypatch):
    monkeypatch.setattr(runner.shutil,'which',lambda x:'/usr/local/bin/'+x)
    for engine in ['dnstt','slipstream']:
        args=runner.cmd_for(engine)
        assert args[0].startswith('/usr/local/bin/')
        assert core.DEFAULTS[engine]['domain'] in str(args)
        assert not any('sh -c' in p for p in args)
