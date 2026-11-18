from duc import dnscheck
from duc.catalog import ENGINES,LABELS

def test_expected_ns_label():
    assert dnscheck.expected_ns('soar','s.akr.cfd')=='ns.akr.cfd'
    assert dnscheck.expected_ns('noizdns','n.akr.cfd')=='ns.akr.cfd'
    import pytest
    with pytest.raises(ValueError):dnscheck.expected_ns('dnstt','n.akr.cfd')

def test_dns_visibility(monkeypatch):
    monkeypatch.setattr(dnscheck.shutil,'which',lambda x:'/usr/bin/dig')
    def fake_dig(rtype,name,resolver):
        if rtype=='NS': return ['sara.ns.cloudflare.com']
        return ['1.1.1.1']
    monkeypatch.setattr(dnscheck,'dig',fake_dig)
    monkeypatch.setattr(dnscheck,'parent_delegation',lambda domain,target,server:True)
    assert dnscheck.check_one('slipstream','r.akr.cfd')['delegated']
    monkeypatch.setattr(dnscheck,'parent_delegation',lambda domain,target,server:False)
    assert not dnscheck.check_one('slipstream','r.akr.cfd')['delegated']

def test_every_engine_dns_checked(monkeypatch):
    monkeypatch.setattr(dnscheck,'check_one',lambda e,d:{'engine':e,'domain':d,'delegated':True})
    profile={e:{'domain':f'{LABELS[e]}.akr.cfd'} for e in ENGINES}
    assert dnscheck.check_all(profile)['verified']==len(ENGINES)

def test_domain_label_consistency(tmp_path,monkeypatch):
    from duc import core
    monkeypatch.setattr(core,'ROOT',tmp_path)
    import pytest
    with pytest.raises(ValueError,match='assigned DNS label'):
        core.update_profile('soar',{'domain':'d.example.com'})
    assert core.update_profile('soar',{'domain':'s.example.com'})['domain']=='s.example.com'


def test_authoritative_referral_parsing():
    from types import SimpleNamespace
    def run(args,**kw):
        assert '+authority' in args and '+norecurse' in args
        return SimpleNamespace(returncode=0,stdout='r.akr.cfd. 300 IN NS ns.akr.cfd.\n',stderr='')
    assert dnscheck.parent_delegation('r.akr.cfd','ns.akr.cfd','sara.ns.cloudflare.com',runner=run)
    assert not dnscheck.parent_delegation('d.akr.cfd','ns.akr.cfd','sara.ns.cloudflare.com',runner=run)
