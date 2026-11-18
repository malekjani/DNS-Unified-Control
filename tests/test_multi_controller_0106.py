import contextlib,json,pathlib,tempfile,unittest
from unittest.mock import patch
from ducmulti import controller,ENGINE_ORDER

class FakeCore:
    def __init__(self,path):
        self.ROOT=path/'etc';self.STATE=path/'state'
        self.ROOT.mkdir();self.STATE.mkdir()
        self.UNITS={x:'dns-unified@'+x+'.service' for x in ENGINE_ORDER if x!='cotten'}
        self.ENGINES=tuple(self.UNITS)
    def profiles(self):return {x:{'domain':x+'.safe.example'} for x in self.ENGINES}
    def check_ready(self,e):return {'ready':True,'issues':[]}
    def list_active(self):return []
    def switch_lock(self):return contextlib.nullcontext()
    def atomic_json(self,p,v):p.write_text(json.dumps(v))
    def audit(self,*args):pass

class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.fake=FakeCore(pathlib.Path(self.tmp.name))
        self.patches=[patch.object(controller,'deps',return_value=self.fake),
            patch.object(controller,'host_ipv4',return_value='172.26.2.194'),
            patch.object(controller,'interface_addresses',return_value=['172.26.2.194','127.0.0.1']),
            patch.object(controller,'tcp_or_udp_listen',return_value=[]),
            patch.object(controller,'active',return_value=False)]
        for p in self.patches:p.start()
    def tearDown(self):
        for p in reversed(self.patches):p.stop()
        self.tmp.cleanup()
    def test_six_existing_engines_plannable_without_mutation(self):
        chosen=[x for x in ENGINE_ORDER if x!='cotten']
        p=controller.plan('multi',chosen)
        self.assertTrue(p['ready'],p['issues'])
        self.assertEqual(len(p['routes']),6)
        self.assertEqual(p['listen_ip'],'172.26.2.194')
        self.assertFalse((self.fake.ROOT/'multi-router.json').exists())
    def test_requested_seven_blocked_if_cotten_not_installed(self):
        p=controller.plan('multi',list(ENGINE_ORDER))
        self.assertFalse(p['ready']);self.assertTrue(any('Cotten' in x for x in p['issues']))
    def test_exclusive_needs_exactly_one_engine(self):
        with self.assertRaises(ValueError):controller.plan('exclusive',['master','soar'])
    def test_wrong_ip_rejected_for_aws_nat(self):
        p=controller.plan('multi',['dnstt'],listen_ip='13.39.238.230')
        self.assertFalse(p['ready']);self.assertIn('Router IP not assigned',p['issues'][0])
    def test_corrupt_state_fails_closed(self):
        (self.fake.STATE/'multi-mode.json').write_text('{bad')
        self.assertEqual(controller.current()['mode'],'unknown')
        self.assertFalse(controller.plan('multi',['dnstt'])['ready'])
    def test_yes_required_for_apply(self):
        with self.assertRaises(ValueError):controller.apply('multi',['dnstt'],confirm='no')

class SwitchSimTests(ControllerTests):
    def test_multi_start_and_exclusive_rollback_on_failure(self):
        for fail_router in (False,True):
            with self.subTest(fail_router=fail_router):
                (self.fake.STATE/'multi-mode.json').unlink(missing_ok=True)
                (self.fake.ROOT/'multi-router.json').unlink(missing_ok=True)
                (self.fake.ROOT/'multi-staging.json').unlink(missing_ok=True)
                running={'dns-unified@soar.service'}
                enabled=set()
                self.fake.list_active=lambda:[e for e,u in self.fake.UNITS.items() if u in running]
                self.fake.is_active=lambda e:self.fake.UNITS[e] in running
                def mock_run(cmd,timeout=30):
                    if cmd[0]!='systemctl':return 0,'',''
                    verb=cmd[1]
                    if verb=='start':
                        if fail_router and cmd[2]==controller.ROUTER_UNIT:return 1,'','injected router failure'
                        running.add(cmd[2])
                    elif verb=='stop':running.discard(cmd[2])
                    elif verb=='enable':enabled.add(cmd[2])
                    elif verb=='disable':enabled.discard(cmd[2])
                    return 0,'',''
                def mock_ss(cmd,timeout=5):
                    if cmd[0]=='ss':
                        lines=[]
                        for e,p in __import__('ducmulti').ENGINE_PORTS.items():
                            if e!='cotten' and f'dns-unified-multi@{e}.service' in running:
                                lines.append(f'udp UNCONN 0 0 127.0.0.1:{p} 0.0.0.0:*')
                        if controller.ROUTER_UNIT in running:
                            lines.extend(['udp UNCONN 0 0 172.26.2.194:53 0.0.0.0:*',
                                          'tcp LISTEN 0 128 172.26.2.194:53 0.0.0.0:*'])
                        return 0,'\n'.join(lines),''
                    return 0,'',''
                with patch.object(controller,'run',side_effect=mock_run), \
                     patch.object(controller,'full_run',side_effect=mock_ss), \
                     patch.object(controller,'active',side_effect=lambda u:u in running), \
                     patch.object(controller,'unit_enabled',side_effect=lambda u:u in enabled), \
                     patch.object(controller,'await_unit',return_value=True), \
                     patch.object(controller,'await_listener',return_value=True):
                    r=controller.apply('multi',['master','dnstt'],confirm='yes')
                    if fail_router:
                        self.assertFalse(r['ok'])
                        self.assertIn('dns-unified@soar.service',running)
                        self.assertEqual(controller.current()['mode'],'exclusive')
                        self.assertNotIn(controller.ROUTER_UNIT,running)
                    else:
                        self.assertTrue(r['ok'],r)
                        self.assertEqual(controller.current()['mode'],'multi')
                        self.assertNotIn('dns-unified@soar.service',running)
                        self.assertIn(controller.ROUTER_UNIT,running)
                        self.assertIn(controller.ROUTER_UNIT,enabled)
