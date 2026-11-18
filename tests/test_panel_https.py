import pytest
from duc.panel_https import panel_record, apply_panel
from duc.cloudflare_dns import ProvisionError, MARKER

class Dummy:
    def __init__(self, entries=None): self.entries=entries or {};self.writes=[]
    def zone(self, domain): return 'z1'
    def records(self, zone, name): return self.entries.get(name, [])
    def call(self, method,path,data): self.writes.append((method,path,data));return {'id':'test'}

def test_panel_plan_is_separate_from_dns_delegation():
    r=panel_record('akr.cfd','1.1.1.1')
    assert r['type']=='A' and r['name']=='panel.akr.cfd' and r['proxied'] is False
    assert MARKER in r['comment']

def test_reject_tunnel_labels_and_ns():
    for label in ('m','r','d','n','v','s','i','c','x','ns'):
        with pytest.raises(ProvisionError): panel_record('akr.cfd','1.1.1.1',label)

def test_reject_injection():
    with pytest.raises(ProvisionError):panel_record('akr.cfd','1.1.1.1','panel { reverse_proxy evil')

def test_panel_record_dry_run():
    d=Dummy()
    r=apply_panel(d,'akr.cfd','1.1.1.1',dry_run=True)
    assert r['action']=='create' and d.writes==[]

def test_panel_record_create():
    d=Dummy()
    r=apply_panel(d,'akr.cfd','1.1.1.1')
    assert r['action']=='create' and len(d.writes)==1
    assert d.writes[0][0]=='POST' and d.writes[0][2]['proxied'] is False

def test_unmanaged_conflict_protected():
    d=Dummy({'panel.akr.cfd':[{'type':'A','name':'panel.akr.cfd','content':'8.8.8.8','id':'a','comment':'other project'}]})
    with pytest.raises(ProvisionError):apply_panel(d,'akr.cfd','1.1.1.1')
    assert d.writes==[]

def test_managed_update():
    d=Dummy({'panel.akr.cfd':[{'type':'A','name':'panel.akr.cfd','content':'8.8.8.8','id':'a','comment':MARKER}]})
    assert apply_panel(d,'akr.cfd','1.1.1.1')['action']=='update'
    assert d.writes[0][0]=='PATCH'
