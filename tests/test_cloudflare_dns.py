import unittest
from duc.cloudflare_dns import record_plan, decide, apply, ProvisionError, MARKER

class DummyClient:
    def __init__(self, entries=None):
        self.entries=entries or {}
        self.writes=[]
    def zone(self, domain):
        assert domain == 'akr.cfd'
        return 'zoneid'
    def records(self, zone, name):
        return self.entries.get(name,[])
    def call(self, method, path, data):
        self.writes.append((method,path,data))
        return {'id':'fake'}

class Tests(unittest.TestCase):
    def test_plan(self):
        a,ns = record_plan('AKR.CFD','203.0.113.9') if False else record_plan('akr.cfd','1.1.1.1')
        self.assertEqual((a['type'],a['name'],a['proxied']),('A','ns.akr.cfd',False))
        self.assertEqual((ns['type'],ns['name'],ns['content']),('NS','v.akr.cfd','ns.akr.cfd'))
    def test_bad_ip(self):
        with self.assertRaises(ProvisionError):record_plan('akr.cfd','127.0.0.1')
    def test_bad_name(self):
        with self.assertRaises(ProvisionError):record_plan('akr.cfd','1.1.1.1','v','v')
    def test_dry_run(self):
        cf=DummyClient()
        r=apply(cf,'akr.cfd','1.1.1.1',dry_run=True)
        self.assertEqual([x['action'] for x in r],['create','create'])
        self.assertEqual(cf.writes,[])
    def test_provision(self):
        cf=DummyClient()
        apply(cf,'akr.cfd','1.1.1.1')
        self.assertEqual([x[0] for x in cf.writes],['POST','POST'])
    def test_exact_unchanged(self):
        want=record_plan('akr.cfd','1.1.1.1')[0]
        self.assertEqual(decide([dict(want,id='z')],want),('unchanged','z'))
    def test_unsafe_conflict(self):
        want=record_plan('akr.cfd','1.1.1.1')[0]
        with self.assertRaises(ProvisionError):decide([dict(want,content='8.8.8.8',id='z',comment='mine')],want)
    def test_managed_update(self):
        want=record_plan('akr.cfd','1.1.1.1')[0]
        self.assertEqual(decide([dict(want,content='8.8.8.8',id='z',comment=MARKER)],want),('update','z'))
    def test_preflight_no_partial_writes(self):
        cf=DummyClient({'v.akr.cfd':[{'type':'CNAME','name':'v.akr.cfd','content':'site.com'}]})
        with self.assertRaises(ProvisionError):apply(cf,'akr.cfd','1.1.1.1')
        self.assertEqual(cf.writes,[])

if __name__=='__main__':unittest.main()
