#!/usr/bin/env bash
# Certificate-only temporary handoff for HTTP-01. Does NOT enable permanent TLS.
# Active services are restarted on both success and failure. Root/TTY required.
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source ./scripts/confirm-yes-no.sh
[[ $EUID == 0 && -t 0 ]] || { echo 'Root and interactive SSH/console required' >&2; exit 1; }
[[ $# == 2 ]] || { echo 'Usage: cert-standalone-handoff.sh PANEL_FQDN PUBLIC_IPV4' >&2; exit 1; }
FQDN=$1
TARGET=$2
python3 - "$FQDN" "$TARGET" <<'PY'
import ipaddress,re,sys
h=sys.argv[1]
assert len(h)<=253 and '.' in h and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',x) for x in h.split('.')), 'Invalid FQDN'
assert ipaddress.ip_address(sys.argv[2]).is_global, 'Invalid public IP'
PY
if ! command -v certbot >/dev/null 2>&1; then
  duc_confirm_yes_no 'Install certbot with apt before certificate request?' || exit 1
  DEBIAN_FRONTEND=noninteractive apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends certbot
fi
command -v dig >/dev/null || { echo 'dig required for A-record verification' >&2; exit 1; }
# Require target DNS first. Cannot pass ACME HTTP-01 through a different VPS.
mapfile -t A_RECORDS < <(dig @1.1.1.1 +short A "$FQDN")
[[ ${#A_RECORDS[@]} -eq 1 && ${A_RECORDS[0]} == "$TARGET" ]] || {
  echo "HTTP-01 blocked: $FQDN public DNS must point exclusively to $TARGET" >&2; exit 1;
}
echo 'CERTIFICATE ONLY: pause existing port owners, issue HTTP-01 certificate, restore ALL originally active services.'
echo 'This does NOT configure SNI routing to the panel; public HTTPS remains PENDING until routed.'
echo 'Potential disruption of active proxies: HAProxy (TCP/80) and Xray (TCP/443).'
duc_confirm_yes_no 'Temporarily interrupt these services for certificate issuance?' || exit 1
# Strictly allow service names we understand; do not kill processes or stop unknown port owners.
for port in 80 443; do
  lines=$(ss -H -ltnp "( sport = :$port )" || true)
  case "$port" in
    80) if [[ -n "$lines" && "$lines" != *'"haproxy"'* ]]; then echo 'Unexpected port 80 owner; refusing' >&2; exit 1; fi ;;
    443) if [[ -n "$lines" && "$lines" != *'"xray"'* ]]; then echo 'Unexpected port 443 owner; refusing' >&2; exit 1; fi ;;
  esac
done
ACTIVE=()
restore() {
  local rc=$?
  trap - EXIT INT TERM
  local restore_error=0 unit
  for unit in "${ACTIVE[@]}"; do
    if ! systemctl start "$unit"; then
      echo "CRITICAL: failed to restore $unit; investigate immediately" >&2
      restore_error=1
    fi
  done
  for unit in "${ACTIVE[@]}"; do
    if ! systemctl is-active --quiet "$unit"; then
      echo "CRITICAL: $unit did not become active" >&2
      restore_error=1
    fi
  done
  if (( restore_error )); then rc=1; fi
  exit "$rc"
}
trap restore EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
# Track BEFORE stopping. Restore exactly those that were running.
for unit in haproxy.service xray.service; do
  if systemctl is-active --quiet "$unit"; then
    ACTIVE+=("$unit")
    systemctl stop "$unit"
  fi
done
if ss -H -ltn "( sport = :80 )" | grep -q .; then
  echo 'Port 80 still occupied after controlled stop; cannot issue certificate' >&2; exit 1
fi
certbot certonly --standalone --non-interactive --agree-tos --register-unsafely-without-email \
  --preferred-challenges http --http-01-port 80 --cert-name "$FQDN" -d "$FQDN"
echo 'CERTIFICATE_ISSUED_ROUTING_PENDING: original services will be restarted now.'
