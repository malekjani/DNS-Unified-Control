"""Regression tests for first-run UX and safe Cloudflare handling."""
from pathlib import Path
import unittest
from unittest import mock
from duc import fresh_setup, guided_setup

ROOT = Path(__file__).resolve().parents[1]
OS = 'ID=ubuntu\nVERSION_ID="24.04"\n'
MEM_LOW = 'MemTotal:       930816 kB\nSwapTotal:       0 kB\n'


class GuidedInstallerTests(unittest.TestCase):
    def case(self, **kwargs):
        base = dict(os_text=OS, mem_text=MEM_LOW, disk_free=30*fresh_setup.GIB,
                    port_text='UNCONN 0 0 127.0.0.54:53 0.0.0.0:*\n'
                              'UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*\n',
                    tcp_text='', existing=False, systemd=True, apt=True)
        base.update(kwargs)
        return fresh_setup.collect(**base)

    def test_initial_audit_has_no_required_domain_or_ip(self):
        report = self.case()
        self.assertIsNone(report['domain'])
        self.assertIsNone(report['intended_ip'])
        self.assertTrue(report['ready_for_base_install'])
        self.assertEqual(report['policy']['dns_mutation_during_install'], False)

    def test_aws_low_ram_stub_does_not_block_base(self):
        report = self.case(domain='m2m.diy', ip='13.39.238.230')
        self.assertTrue(report['ready_for_base_install'])
        warning_ids = {x['id'] for x in report['checks'] if x['status'] == 'warn'}
        self.assertIn('memory', warning_ids)
        self.assertIn('udp53', warning_ids)

    def test_any_udp53_wildcard_is_different_from_stub(self):
        report = self.case(port_text='UNCONN 0 0 0.0.0.0:53 0.0.0.0:*\n')
        entry = next(x for x in report['checks'] if x['id'] == 'udp53')
        self.assertIn('Non-loopback', entry['message'])
        self.assertFalse(report['ready_for_base_install'])

    def test_control_port_conflict_blocks(self):
        report = self.case(tcp_text='LISTEN 0 128 127.0.0.1:1080 0.0.0.0:*\n')
        self.assertFalse(report['ready_for_base_install'])
        self.assertIn('tcp_1080', {x['id'] for x in report['checks']})

    def test_blocking_conflict_stops(self):
        report = self.case(existing=True)
        self.assertFalse(report['ready_for_base_install'])

    def test_cf_zone_verification_is_read_only_and_no_token_printed(self):
        token = 'VerySecretNotToAppear'
        class FakeCF:
            def __init__(self, value):
                assert value == token
            def zone(self, domain):
                assert domain == 'm2m.diy'
                return 'zone123'
        with mock.patch('builtins.print') as printer:
            assert guided_setup.verify_cloudflare('m2m.diy', prompt=lambda _: token,
                                                  client_type=FakeCF) is True
        assert token not in str(printer.call_args_list)

    def test_cf_no_token_does_not_contact_api(self):
        assert guided_setup.verify_cloudflare('m2m.diy', prompt=lambda _: '',
                                              client_type=lambda _: 1) is False

    def test_shell_default_guided_and_old_flags_preserved(self):
        script = (ROOT/'scripts/fresh-install.sh').read_text()
        self.assertIn('ACTION=--guided', script)
        self.assertIn('--audit|--install|--postcheck|--guided', script)
        self.assertIn('python3 -m duc.fresh_setup audit "${args[@]}" --gate', script)
        self.assertIn('Cloudflare token is NEVER saved', script)
        self.assertIn('ACTION=--install', script)

    def test_swap_script_never_overwrites_existing(self):
        script = (ROOT/'scripts/ensure-swap.sh').read_text()
        self.assertIn('Refusing to overwrite existing data', script)
        self.assertIn('chmod 0600', script)


if __name__ == '__main__':
    unittest.main()
