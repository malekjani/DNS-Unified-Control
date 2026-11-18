"""Web setup readiness: a working local TUI is not a completed public Web installation.

No Cloudflare token is read or retained by this module. No remote mutations.
"""
from __future__ import annotations

from pathlib import Path
import configparser
import re
import subprocess


LE_LIVE = Path('/etc/letsencrypt/live')
LE_RENEWAL = Path('/etc/letsencrypt/renewal')


def certificate_status(fqdn: str, *, live_dir: Path = LE_LIVE,
                       renewal_dir: Path = LE_RENEWAL,
                       run=subprocess.run) -> dict:
    """Check certificate name, 7-day expiry guard and usable renewal config.

    Probe only local files and openssl; never open or print Cloudflare tokens.
    """
    cert = live_dir / fqdn / 'fullchain.pem'
    if not cert.is_file():
        return {'certificate': 'MISSING', 'renewal': 'NOT_CONFIGURED'}
    for args in (['openssl', 'x509', '-in', str(cert), '-noout', '-checkhost', fqdn],
                 ['openssl', 'x509', '-in', str(cert), '-noout', '-checkend', '604800']):
        try:
            result = run(args, capture_output=True, text=True, timeout=7, check=False)
        except (OSError, subprocess.TimeoutExpired):
            return {'certificate': 'UNVERIFIABLE', 'renewal': 'UNKNOWN'}
        if result.returncode != 0:
            return {'certificate': 'INVALID_OR_EXPIRING', 'renewal': 'UNKNOWN'}
    config = renewal_dir / (fqdn + '.conf')
    if not config.is_file():
        return {'certificate': 'VALID', 'renewal': 'NOT_CONFIGURED'}
    try:
        text = config.read_text(encoding='utf-8')
    except (OSError, UnicodeError):
        return {'certificate': 'VALID', 'renewal': 'UNKNOWN'}
    # Caddy/other ACME providers must have their own audited renewal status.
    match = re.search(r'^\s*dns_cloudflare_credentials\s*=\s*(.+?)\s*$', text, re.MULTILINE)
    if not match:
        return {'certificate': 'VALID', 'renewal': 'NEEDS_REVIEW'}
    creds = Path(match.group(1).strip().strip('"').strip("'"))
    try:
        if (not creds.is_absolute() or not creds.is_file() or creds.is_symlink() or
                creds.stat().st_mode & 0o077):
            return {'certificate': 'VALID', 'renewal': 'BROKEN'}
    except OSError:
        return {'certificate': 'VALID', 'renewal': 'BROKEN'}
    return {'certificate': 'VALID', 'renewal': 'CONFIGURED'}


def web_components(tls: dict, cert: dict, *, tui_ready: bool = True) -> dict:
    """Full Web READY requires valid certificate, renewable credentials, local
    trusted TLS/DUC page, and public panel A pointing to the instance.
    """
    tls_ok = tls.get('status') == 'VERIFIED'
    dns_ok = tls.get('dns') == 'TARGET_IP'
    cert_ok = cert.get('certificate') == 'VALID' or tls_ok
    renewable = cert.get('renewal') == 'CONFIGURED'
    web_ok = tui_ready and tls_ok and dns_ok and cert_ok and renewable
    return {
        'tui': {'status': 'READY' if tui_ready else 'INCOMPLETE'},
        'web': {
            'status': 'READY' if web_ok else 'INCOMPLETE',
            'certificate': cert.get('certificate', 'UNKNOWN'),
            'renewal': cert.get('renewal', 'UNKNOWN'),
            'https_route': tls.get('status', 'UNKNOWN'),
            'panel_dns': tls.get('dns', 'UNKNOWN'),
        },
    }
