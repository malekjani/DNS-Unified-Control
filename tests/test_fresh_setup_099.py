"""Offline tests: first-run assessment must be read-only and fail closed."""
import json
import unittest
from unittest import mock
from duc import fresh_setup

OS = 'ID=ubuntu\nVERSION_ID="24.04"\n'
MEM = 'MemTotal:     2097152 kB\nSwapTotal:  1048576 kB\n'


def sample(**overrides):
    params = dict(domain='m2m.diy', ip='203.0.113.123', os_text=OS, mem_text=MEM,
                  disk_free=10 * fresh_setup.GIB, port_text='', tcp_text='', existing=False,
                  systemd=True, apt=True)
    # test-only address 203.0.113.123 is not accepted as a real public address;
    # override with actual known global address for offline logic validation.
    params['ip'] = '1.1.1.1'
    params.update(overrides)
    return fresh_setup.collect(**params)


class FreshSetupTests(unittest.TestCase):
    def test_clean_system_ready(self):
        report = sample()
        self.assertTrue(report['ready_for_base_install'])
        self.assertEqual(report['schema'], 'duc.fresh-preflight.v1')
        self.assertFalse(report['policy']['dns_mutation_during_install'])
        self.assertFalse(report['policy']['start_dns_engine_during_install'])

    def test_old_state_refused(self):
        self.assertFalse(sample(existing=True)['ready_for_base_install'])

    def test_explicit_resume(self):
        self.assertTrue(sample(existing=True, resume=True)['ready_for_base_install'])

    def test_low_disk_blocks(self):
        self.assertFalse(sample(disk_free=fresh_setup.GIB)['ready_for_base_install'])

    def test_low_ram_no_swap_blocks(self):
        x = sample(mem_text='MemTotal: 262144 kB\nSwapTotal: 0 kB\n')
        self.assertFalse(x['ready_for_base_install'])

    def test_udp53_reports_manual_remediation(self):
        x = sample(port_text='UNCONN 0 0 127.0.0.53:53 0.0.0.0:*\n')
        entry = next(y for y in x['checks'] if y['id'] == 'udp53')
        self.assertEqual(entry['status'], 'warn')
        self.assertIn('resolv.conf', entry['remedy'])

    def test_public_ip_validation(self):
        for ip in ('192.168.1.1', '127.0.0.1', '2001:db8::1', 'test;echo'):
            with self.subTest(ip=ip), self.assertRaises(ValueError):
                sample(ip=ip)

    def test_domain_validation(self):
        for domain in ('x/../../etc', 'm2m.diy; echo x', 'localhost', 'example..com'):
            with self.subTest(domain=domain), self.assertRaises(ValueError):
                sample(domain=domain)

    def test_bad_systemd(self):
        self.assertFalse(sample(systemd=False)['ready_for_base_install'])

    def test_plan_follows_gate(self):
        r = sample(apt=False)
        self.assertEqual(r['actions'][0]['state'], 'blocked')
        self.assertEqual(r['actions'][-1]['state'], 'pending-operator')

    def test_ss_parsing(self):
        s = 'UNCONN 0 0 0.0.0.0:53 0.0.0.0:*\nUNCONN 0 0 127.0.0.1:5353 0.0.0.0:*'
        self.assertEqual(fresh_setup.parse_ss_udp53(s), ['0.0.0.0:53'])

    def test_no_dns_write_on_audit(self):
        with mock.patch.object(fresh_setup.subprocess, 'run', side_effect=AssertionError('Not needed')):
            r = sample()
        self.assertFalse(r['policy']['dns_mutation_during_install'])

    def test_output_json_roundtrip(self):
        self.assertEqual(json.loads(json.dumps(sample()))['intended_ip'], '1.1.1.1')


if __name__ == '__main__':
    unittest.main()

# Additional fail-closed tests are intentionally included outside the old classes;
# pytest collects them alongside the regular project regression suite.
def test_profile_initialization_rejects_nondefault_domain(tmp_path, monkeypatch):
    from duc import core, fresh_setup
    monkeypatch.setattr(fresh_setup.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(core, 'ROOT', tmp_path)
    monkeypatch.setattr(core, 'list_active', lambda: [])
    data = core.profiles()
    data['noizdns']['domain'] = 'n.otherdomain.net'
    core.atomic_json(tmp_path / 'profiles.json', data)
    try:
        fresh_setup.configure_domains('m2m.diy')
    except RuntimeError as err:
        assert 'refusing overwrite' in str(err)
    else:
        raise AssertionError('existing custom domain was silently overwritten')


def test_profile_initialization_assigns_unique_engine_labels(tmp_path, monkeypatch):
    from duc import core, fresh_setup
    monkeypatch.setattr(fresh_setup.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(core, 'ROOT', tmp_path)
    monkeypatch.setattr(core, 'list_active', lambda: [])
    result = fresh_setup.configure_domains('m2m.diy')
    assert result['dns_records_mutated'] is False
    assert result['domains']['noizdns'] == 'n.m2m.diy'
    assert len(set(result['domains'].values())) == len(result['domains']) == 9
