#!/usr/bin/env bash
# Explicit, interactive opt-in. Does not modify the nine tunnel DNS delegations.
set -Eeuo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/confirm-yes-no.sh"
if [[ $EUID -ne 0 ]]; then echo 'Run with sudo' >&2; exit 1; fi
if [[ ! -t 0 ]]; then echo 'Run interactively: sudo bash scripts/setup-panel-https.sh' >&2; exit 1; fi
command -v apt-get >/dev/null || { echo 'Debian/Ubuntu apt required' >&2; exit 1; }
command -v ss >/dev/null || { echo 'Missing ss (iproute2)' >&2; exit 1; }
PY=/opt/dns-unified-control/.venv/bin/python
if [[ ! -x "$PY" || ! -f /opt/dns-unified-control/duc/panel_https.py ]]; then
  echo 'Install or upgrade DNS Unified Control first (sudo bash install.sh)' >&2; exit 1
fi
printf 'Cloudflare zone (e.g. akr.cfd): '
read -r DOMAIN
printf 'Panel label [panel]: '
read -r LABEL
LABEL="${LABEL:-panel}"
# Validation protects the generated Caddyfile against arbitrary content injection.
FQDN=$(PYTHONPATH=/opt/dns-unified-control "$PY" - "$DOMAIN" "$LABEL" <<'PY'
import sys
from duc.panel_https import panel_record
try:
    print(panel_record(sys.argv[1], '1.1.1.1', sys.argv[2])['name'])
except Exception as exc:
    print('Invalid hostname: ' + str(exc), file=sys.stderr); sys.exit(1)
PY
)

if [[ -f /etc/caddy/Caddyfile ]] && ! grep -q '^# managed-by:dns-unified-control' /etc/caddy/Caddyfile; then
  if command -v caddy >/dev/null 2>&1; then
    echo 'Existing Caddy configuration belongs to another application. Refusing to overwrite.' >&2
    echo "See docs/PANEL_HTTPS.md to add ${FQDN} manually." >&2
    exit 1
  fi
fi
if ! command -v caddy >/dev/null 2>&1; then
  if ss -ltnH | awk '{print $4}' | grep -Eq '(^|:)(80|443)$'; then
    echo 'TCP 80 or 443 already occupied. Refusing to replace another web service.' >&2; exit 1
  fi
fi
printf 'Public IPv4 of VPS (empty = detect automatically): '
read -r IP
printf '\nWill prepare HTTPS for https://%s\n' "$FQDN"
echo 'Requirements: Public TCP 80/443 allowed, Cloudflare zone active, no conflicting reverse proxy.'
if ! duc_confirm_yes_no 'Proceed with Cloudflare DNS and Caddy setup?'; then echo 'Cancelled'; exit 0; fi
# One-time token is entered without echo by the Python tool. Never saved to disk.
if [[ -n "$IP" ]]; then
  PYTHONPATH=/opt/dns-unified-control "$PY" -m duc.panel_https --domain "$DOMAIN" --label "$LABEL" --ip "$IP"
else
  PYTHONPATH=/opt/dns-unified-control "$PY" -m duc.panel_https --domain "$DOMAIN" --label "$LABEL"
fi

if ! command -v caddy >/dev/null 2>&1; then
  echo 'Installing distribution Caddy package (no curl|bash installer)...'
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y caddy
fi
# Permit managing existing Caddyfile only when it is from us or the package's
# initial default. On first setup, the package may install a default Caddyfile.
if [[ -f /etc/caddy/Caddyfile ]] && ! grep -q '^# managed-by:dns-unified-control' /etc/caddy/Caddyfile; then
  if ! grep -q 'root \* /usr/share/caddy' /etc/caddy/Caddyfile; then
    echo 'Custom /etc/caddy/Caddyfile detected; no config overwritten.' >&2
    echo "Manual setup: docs/PANEL_HTTPS.md (${FQDN})" >&2; exit 1
  fi
fi
if ss -ltnp | grep -E '(:80[[:space:]]|:443[[:space:]])' | grep -v -q 'caddy'; then
  echo 'Port 80 or 443 appears in use by another server; refusing to change listeners.' >&2
  exit 1
fi
mkdir -p /etc/caddy
umask 022
TMP=$(mktemp /etc/caddy/.duc-caddy.XXXXXX)
trap 'rm -f "$TMP"' EXIT
cat > "$TMP" <<EOF
# managed-by:dns-unified-control
# Public TLS site only. Does NOT affect UDP 53 or tunnel DNS records.
{
    servers :443 {
        protocols h1 h2
    }
}
${FQDN} {
    encode zstd gzip
    header Strict-Transport-Security "max-age=2592000"
    header X-Content-Type-Options "nosniff"
    reverse_proxy 127.0.0.1:8088 {
        header_up X-DUC-Client-IP {remote_host}
    }
}
EOF
# Check syntax before changing any existing file.
caddy validate --config "$TMP" --adapter caddyfile
if [[ -f /etc/caddy/Caddyfile ]]; then
  cp -a /etc/caddy/Caddyfile "/etc/caddy/Caddyfile.duc-backup-$(date +%Y%m%d-%H%M%S)"
fi
install -m 0644 "$TMP" /etc/caddy/Caddyfile
systemctl enable --now caddy
systemctl reload caddy || systemctl restart caddy
# Set Secure session cookies only when TLS configuration was accepted locally.
install -d -m 0755 /etc/systemd/system/dns-unified-web.service.d
cat > /etc/systemd/system/dns-unified-web.service.d/https.conf <<EOF
[Service]
Environment=DUC_COOKIE_SECURE=1
Environment=DUC_TRUST_LOCAL_PROXY=1
EOF
systemctl daemon-reload
systemctl restart dns-unified-web.service
printf '\nCaddy configured. Verify ACME issuance (it depends on live DNS + reachable TCP 80/443):\n'
printf '  sudo journalctl -u caddy -n 70 --no-pager\n  curl -I https://%s\n' "$FQDN"
printf 'Panel: https://%s\n' "$FQDN"
echo 'Important: Public dashboard. Restrict access using firewall IP allowlisting or Cloudflare Access as documented.'
