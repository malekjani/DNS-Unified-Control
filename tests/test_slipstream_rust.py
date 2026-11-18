"""Specific regression tests for Mygod/slipstream-rust integration."""
from pathlib import Path
import pytest
from duc import core, runner

@pytest.fixture
def paths(tmp_path, monkeypatch):
    monkeypatch.setattr(core, 'ROOT',tmp_path/'config')
    monkeypatch.setattr(core, 'STATE',tmp_path/'state')
    monkeypatch.setattr(runner, 'ROOT',tmp_path/'config')
    monkeypatch.setattr(runner.shutil, 'which',lambda s:'/usr/local/bin/'+s)
    return tmp_path

def test_rust_binary_is_distinct_from_old_c():
    assert core.BINARIES['slipstream']=='slipstream-rust-server'
    assert core.NAMES['slipstream']=='SlipStream Rust'

def test_rust_cli_flags(paths):
    c=dict(core.DEFAULTS['slipstream'])
    c.update(domain='r.akr.cfd',udp_port=53,target='127.0.0.1:22',max_connections=512,
             idle_timeout_seconds=90,dns_listen_host='0.0.0.0')
    args=runner.cmd_for('slipstream',c)
    assert args[0]=='/usr/local/bin/slipstream-rust-server'
    assert args[args.index('--domain')+1]=='r.akr.cfd'
    assert args[args.index('--dns-listen-port')+1]=='53'
    assert args[args.index('--dns-listen-host')+1]=='0.0.0.0'
    assert args[args.index('--target-address')+1]=='127.0.0.1:22'
    assert args[args.index('--max-connections')+1]=='512'
    assert args[args.index('--idle-timeout-seconds')+1]=='90'
    for f in ('--cert','--key','--reset-seed'):
        assert args[args.index(f)+1].startswith(str(core.ROOT/'keys'))
    assert not any('sh -c' in v or ';' in v for v in args)

def test_preflight_requires_certificate_key_seed(paths, monkeypatch):
    from duc import dante
    monkeypatch.setattr(dante,'status',lambda:{'ready':True})
    ready=core.check_ready('slipstream',{'domain':'r.akr.cfd',**{k:v for k,v in core.DEFAULTS['slipstream'].items() if k!='domain'}})
    assert not ready['ready']
    for name in ('slipstream-rust.crt','slipstream-rust.key','slipstream-rust.reset-seed'):
        assert any(name in issue for issue in ready['issues'])
    keys=core.ROOT/'keys';keys.mkdir(parents=True)
    for name in ('slipstream-rust.crt','slipstream-rust.key','slipstream-rust.reset-seed'):
        (keys/name).write_text('a'*32 if name.endswith('.reset-seed') else 'test')
        (keys/name).chmod(0o600)
    ready=core.check_ready('slipstream',{**core.DEFAULTS['slipstream'],'domain':'r.akr.cfd'})
    assert ready['ready']

def test_resolver_input_validation(paths):
    assert core.validate('client_resolvers','1.1.1.1:53, [2606:4700:4700::1111]:53')=='1.1.1.1:53,[2606:4700:4700::1111]:53'
    assert core.validate('client_authoritative','')==''
    for value in ('1.1.1.1:53;rm -rf /','1.1.1.1:53,1.1.1.1:53',
                  '8.8.8.8:0','example.com:53','[invalid]:53'):
        with pytest.raises(ValueError):core.validate('client_resolvers',value)
    with pytest.raises(ValueError):core.update_profile('slipstream',{'client_resolvers':'', 'client_authoritative':''})
    with pytest.raises(ValueError):core.update_profile('slipstream',{'client_authoritative':'1.1.1.1:53'})
    with pytest.raises(ValueError):core.update_profile('slipstream',{'client_cc':'malicious'})

def test_compatible_config_migration(paths):
    core.ROOT.mkdir(parents=True)
    core.atomic_json(core.ROOT/'profiles.json',{'slipstream':{'domain':'r.akr.cfd','udp_port':53,'target':'127.0.0.1:22'}})
    c=core.profiles()['slipstream']
    assert c['domain']=='r.akr.cfd'
    assert c['max_connections']==256
    assert c['client_keep_alive']==400


def test_systemd_unit_has_importable_working_directory():
    unit=Path(__file__).resolve().parents[1]/'deploy/dns-unified@.service'
    assert 'WorkingDirectory=/opt/dns-unified-control' in unit.read_text()
