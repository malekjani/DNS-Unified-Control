#!/usr/bin/env bash
# Cloudflare DNS-01 is part of Web install completion; never alters A/NS or listeners.
# Root-only persistent credential storage is optional and requires explicit yes.
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source ./scripts/confirm-yes-no.sh
[[ $EUID -eq 0 && -t 0 ]] || { echo 'Requires root and interactive SSH/console' >&2; exit 1; }
[[ $# -eq 1 ]] || { echo 'Usage: cert-cloudflare-dns01.sh panel.example.org' >&2; exit 1; }
FQDN=$1
python3 - "$FQDN" <<'PY'
import re,sys
host=sys.argv[1]
if len(host)>253 or '.' not in host or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part) for part in host.split('.')):
    raise SystemExit('Invalid panel FQDN')
PY
if ! command -v certbot >/dev/null 2>&1 || ! certbot plugins 2>/dev/null | grep -q 'dns-cloudflare'; then
  echo 'Certbot + Cloudflare DNS plugin are required for Web installation.'
  duc_confirm_yes_no 'Install ACME dependencies using apt now?' || exit 1
  DEBIAN_FRONTEND=noninteractive apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends certbot python3-certbot-dns-cloudflare
  certbot plugins 2>/dev/null | grep -q 'dns-cloudflare' || { echo 'Cloudflare Certbot plugin missing' >&2; exit 1; }
fi
CERT="/etc/letsencrypt/live/$FQDN/fullchain.pem"
RENEW="/etc/letsencrypt/renewal/$FQDN.conf"
ALREADY_VALID=false
if [[ -r "$CERT" ]] && openssl x509 -in "$CERT" -noout -checkhost "$FQDN" >/dev/null 2>&1 && openssl x509 -in "$CERT" -noout -checkend 604800 >/dev/null 2>&1; then
  ALREADY_VALID=true
fi
if [[ "$ALREADY_VALID" == true ]]; then
  echo 'Existing TLS certificate is still valid. Checking Certbot renewal credentials.'
  if [[ -r "$RENEW" ]]; then
    OLD_CRED=$(sed -n 's/^[[:space:]]*dns_cloudflare_credentials[[:space:]]*=[[:space:]]*//p' "$RENEW" | tail -n 1)
    if [[ -n "$OLD_CRED" && "$OLD_CRED" == /* && -f "$OLD_CRED" && ! -L "$OLD_CRED" ]] && [[ $(stat -c %a "$OLD_CRED") == 600 ]]; then
      echo 'Existing Cloudflare renewal credential path is present; no new issuance necessary.'
      exit 0
    fi
  fi
  echo 'CERTIFICATE_RENEWAL_BROKEN: prior one-time Cloudflare credentials are missing.'
  duc_confirm_yes_no 'Reconfigure automatic renewal with a new restricted token?' || exit 1
else
  echo "Web certificate required for $FQDN; does not alter DNS A/NS or stop Xray/HAProxy."
  duc_confirm_yes_no 'Request a Cloudflare DNS-01 certificate now?' || exit 1
fi

# Do not store a zone-wide token unless the user explicitly approves.
echo 'Cloudflare token needs Zone DNS Edit; scope it to this one zone.'
PERSIST=false
if duc_confirm_yes_no 'Store DNS-01 credential root-only for automatic renewal?'; then
  PERSIST=true
else
  if [[ "$ALREADY_VALID" == true ]]; then
    echo 'Cannot repair renewal without storing a credential; existing certificate remains usable until expiry.' >&2
    exit 1
  fi
  echo 'WARNING: one-time certificate will NOT be renewable automatically. Web setup stays INCOMPLETE.'
fi

umask 077
TMP=$(mktemp /run/duc-cloudflare-dns01.XXXXXXXX)
cleanup() { rm -f -- "$TMP"; }
trap cleanup EXIT
IFS= read -r -s -p 'Cloudflare DNS Edit API token (hidden): ' TOKEN || { echo 'Missing token' >&2; exit 1; }
printf '\n'
[[ -n "$TOKEN" ]] || { echo 'Empty token rejected' >&2; exit 1; }
printf 'dns_cloudflare_api_token = %s\n' "$TOKEN" > "$TMP"
unset TOKEN
chmod 600 "$TMP"
if [[ "$PERSIST" == true ]]; then
  install -d -m 0700 -o root -g root /etc/letsencrypt/duc-dns01
  CREDENTIALS="/etc/letsencrypt/duc-dns01/$FQDN.ini"
  if [[ -L "$CREDENTIALS" ]]; then echo 'Refusing symlink credential target' >&2; exit 1; fi
  # Atomic installation of root-only token file; no output includes its contents.
  STAGING=$(mktemp /etc/letsencrypt/duc-dns01/.token.XXXXXXXX)
  chmod 600 "$STAGING"
  cp "$TMP" "$STAGING"
  mv -f -- "$STAGING" "$CREDENTIALS"
else
  CREDENTIALS="$TMP"
fi

if [[ "$ALREADY_VALID" == true ]]; then
  # Certbot reconfigure performs an ACME validation before changing renewal config;
  # no needless forced renewal of a newly issued certificate.
  certbot reconfigure --non-interactive --cert-name "$FQDN" \
    --dns-cloudflare --dns-cloudflare-credentials "$CREDENTIALS" \
    --dns-cloudflare-propagation-seconds 45
  echo 'RENEWAL_RECONFIGURED: certificate preserved, automatic DNS-01 credential file installed.'
else
  certbot certonly --non-interactive --agree-tos --register-unsafely-without-email \
    --dns-cloudflare --dns-cloudflare-credentials "$CREDENTIALS" \
    --dns-cloudflare-propagation-seconds 45 --cert-name "$FQDN" -d "$FQDN"
  echo "CERTIFICATE_ISSUED_ROUTING_PENDING: /etc/letsencrypt/live/$FQDN/"
fi
echo 'WEB COMPLETION still requires actual trusted TLS/SNI proxy routing to 127.0.0.1:8088 and correct public A.'
