import pathlib
import pytest
from duc import core,runner
from duc.catalog import ENGINES,LABELS,METHODS
from duc.cloudflare_dns import record_plan_all, apply_all, ProvisionError

def test_nine_engines_no_collision():
    assert len(ENGINES)==9
    assert len(set(LABELS.values()))==len(ENGINES)
    assert all(core.DEFAULTS[e]['domain'].startswith(LABELS[e]+'.') for e in ENGINES)
    assert 'DoH client' in METHODS['vaydns']
    assert 'mKCP' in METHODS['xdns']

def test_cloudflare_all_records():
    plan=record_plan_all('AKR.CFD','1.1.1.1')
    assert len(plan)==1+len(ENGINES)
    assert plan[0]['type']=='A' and plan[0]['proxied'] is False
    assert {r['name'] for r in plan[1:]}=={f'{x}.akr.cfd' for x in LABELS.values()}
    assert all(r['content']=='ns.akr.cfd' for r in plan[1:])
    with pytest.raises(ProvisionError):record_plan_all('akr.cfd','1.1.1.1',host='d')

class CFMock:
    def __init__(self,bad=None): self.bad=bad;self.writes=[]
    def zone(self,domain): return 'zone'
    def records(self,zone,name):
        if name==self.bad:return [{'type':'CNAME','name':name,'content':'bad.com'}]
        return []
    def call(self,method,path,data=None):self.writes.append((method,path,data))

def test_all_preflight_is_before_writes():
    mock=CFMock('x.akr.cfd')
    with pytest.raises(ProvisionError):apply_all(mock,'akr.cfd','1.1.1.1')
    assert mock.writes==[]
    mock=CFMock()
    result=apply_all(mock,'akr.cfd','1.1.1.1',dry_run=True)
    assert len(result)==10 and not mock.writes
    apply_all(mock,'akr.cfd','1.1.1.1')
    assert len(mock.writes)==10

def test_strict_bool_and_enums():
    assert core.validate('dnstt_compat',True) is True
    with pytest.raises(ValueError):core.validate('dnstt_compat','true')
    with pytest.raises(ValueError):core.validate('record_type','txt; rm -rf /')
    with pytest.raises(ValueError):core.validate('soar_allow_ports','any')

def test_engine_commands(tmp_path,monkeypatch):
    monkeypatch.setattr(runner,'ROOT',tmp_path)
    monkeypatch.setattr(runner.shutil,'which',lambda s:'/usr/local/bin/'+s)
    d=runner.cmd_for('vaydns',core.DEFAULTS['vaydns'])
    assert d[:3]==['/usr/local/bin/vaydns-server','-udp',':53']
    assert '-record-type' in d and '-mtu' in d
    conf=dict(core.DEFAULTS['vaydns'],dnstt_compat=True)
    assert '-dnstt-compat' in runner.cmd_for('vaydns',conf)
    cmd=runner.cmd_for('soar',core.DEFAULTS['soar'])
    assert cmd[1:3]==['-zone','s.example.com']
    cmd=runner.cmd_for('xdns',core.DEFAULTS['xdns'])
    assert cmd[1:3]==['run','-c']
    assert 'server.json' in cmd[-1]

def test_web_has_dns_and_methods_tabs():
    base=pathlib.Path(__file__).resolve().parent.parent
    html=(base/'web/index.html').read_text()
    assert 'data-tab="dns"' in html and 'data-tab="methods"' in html
