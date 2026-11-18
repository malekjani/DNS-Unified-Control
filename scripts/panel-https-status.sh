#!/usr/bin/env bash
# Read-only status, distinguishes installed web panel from issued TLS certificate.
set -Eeuo pipefail
INSTANCE=/etc/dns-unified/instance.json
if [[ ! -r "$INSTANCE" ]]; then
  echo 'PANEL_HTTPS=UNCONFIGURED (instance missing)'; exit 0
fi
fqdn=$(python3 - "$INSTANCE" <<'PYCODE'
import json,sys
print(json.load(open(sys.argv[1]))['panel_fqdn'])
PYCODE
)
public_ip=$(python3 - "$INSTANCE" <<'PYCODE'
import json,sys
print(json.load(open(sys.argv[1]))['public_ipv4'])
PYCODE
)
# A pre-existing TLS gateway (Xray/HAProxy) may route panel SNI; verify the
# actual served DUC login page and trusted certificate, not the daemon name.
html=$(curl -fsS --noproxy '*' --connect-timeout 2 --max-time 7 \
  --resolve "$fqdn:443:127.0.0.1" "https://$fqdn/" 2>/dev/null || true)
if [[ "$html" == *'<title>DNS Unified Control</title>'* ]]; then
  echo "PANEL_HTTPS=VERIFIED fqdn=$fqdn (trusted TLS + DUC page via local :443)"
elif ss -H -ltn "( sport = :443 )" | grep -q .; then
  echo "PANEL_HTTPS=PENDING fqdn=$fqdn (TCP/443 occupied, DUC SNI/TLS route unverified)"
else
  echo "PANEL_HTTPS=DEFERRED fqdn=$fqdn (no local TCP/443 HTTPS listener)"
fi
if command -v dig >/dev/null 2>&1; then
  addresses=$(dig @1.1.1.1 +tries=1 +time=2 +short A "$fqdn" 2>/dev/null || true)
  if printf '%s\n' "$addresses" | grep -Fxq "$public_ip"; then
    echo 'PANEL_DNS=TARGET_IP (public DNS points to this instance)'
  else
    echo "PANEL_DNS=OTHER_OR_UNRESOLVED (not pointing at $public_ip; cutover is a separate approved action)"
  fi
fi
