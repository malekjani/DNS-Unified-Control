"""Install-path regressions found on the first AWS deployment."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

class InstallRuntimeRegressions(unittest.TestCase):
    def test_first_install_runtime_permissions_are_repaired_before_web_start(self):
        s = (ROOT/'install.sh').read_text()
        self.assertLess(s.index('bash ./scripts/ensure-runtime-access.sh'), s.index('systemctl enable --now dns-unified-agent.socket dns-unified-web.service'))
        self.assertLess(s.index('bash ./scripts/check-local-health.sh'), s.index('=== Soar server auto-provision'))
        self.assertIn('systemctl reset-failed dns-unified-web.service', s)

    def test_permission_repair_is_scoped_to_opt_not_secrets(self):
        s = (ROOT/'scripts/ensure-runtime-access.sh').read_text()
        self.assertIn('chgrp -R dns-unified', s)
        self.assertIn('chmod -R g+rX,g-w', s)
        self.assertIn('runuser -u dns-unified --', s)
        self.assertNotIn('chmod -R 777', s)
        self.assertNotIn('chgrp -R dns-unified /etc/', s)

    def test_web_local_readiness_fails_instead_of_masking(self):
        s = (ROOT/'scripts/check-local-health.sh').read_text()
        self.assertIn('curl --noproxy', s)
        self.assertIn('systemctl is-active --quiet dns-unified-web.service', s)
        self.assertIn("fail 'Web service did not answer HTTP", s)
        self.assertIn('systemctl is-active --quiet dns-unified-agent.socket', s)
        fresh = (ROOT/'scripts/fresh-install.sh').read_text()
        self.assertNotIn('systemctl is-active dns-unified-web.service dns-unified-agent.socket || true', fresh)
        self.assertIn('bash ./scripts/check-local-health.sh', fresh)

    def test_installer_never_claims_public_tls_without_check(self):
        fresh = (ROOT/'scripts/fresh-install.sh').read_text()
        tls = (ROOT/'scripts/panel-https-status.sh').read_text()
        self.assertIn('bash ./scripts/panel-https-status.sh', fresh)
        self.assertIn('PANEL_HTTPS=DEFERRED', tls)
        self.assertIn('PANEL_HTTPS=VERIFIED', tls)
        self.assertIn('--resolve "$fqdn:443:127.0.0.1"', tls)
        self.assertIn('DNS-01', fresh)
        self.assertNotIn('setup-panel-https.sh', fresh)

    def test_shell_syntax(self):
        for name in ('install.sh','scripts/fresh-install.sh','scripts/ensure-runtime-access.sh',
                     'scripts/check-local-health.sh','scripts/panel-https-status.sh'):
            p = subprocess.run(['bash','-n', str(ROOT/name)], capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, msg=f'{name}: {p.stderr}')

if __name__=='__main__': unittest.main()
