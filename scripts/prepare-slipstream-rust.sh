#!/usr/bin/env bash
# Generate TLS leaf certificate, private key, and persistent QUIC reset seed.
set -Eeuo pipefail
if [[ ${EUID} -ne 0 ]]; then echo 'Use sudo bash scripts/prepare-slipstream-rust.sh' >&2; exit 1; fi
command -v openssl >/dev/null || { echo 'Install openssl first' >&2; exit 1; }
DEST=/etc/dns-unified/keys
install -d -m 0700 -o root -g root "$DEST"
crt="$DEST/slipstream-rust.crt"
key="$DEST/slipstream-rust.key"
seed="$DEST/slipstream-rust.reset-seed"
if [[ -e "$crt" || -e "$key" ]]; then
  if [[ ! -s "$crt" || ! -s "$key" ]]; then echo 'Certificate/key incomplete; inspect before proceeding' >&2; exit 1; fi
  echo 'Existing certificate/key preserved'
else
  umask 077
  openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 365 \
    -subj '/CN=slipstream-rust' -keyout "$key" -out "$crt"
fi
if [[ ! -e "$seed" ]]; then
  umask 077
  openssl rand -hex 16 | tr -d '\n' > "$seed"
fi
chmod 0600 "$key" "$seed"
chmod 0644 "$crt"
chown root:root "$key" "$crt" "$seed"
[[ $(wc -c < "$seed") -eq 32 ]] || { echo 'Invalid reset seed length (expected 32 hex digits)' >&2; exit 1; }
openssl x509 -in "$crt" -noout -dates -fingerprint -sha256
printf '\nKeep the private key secret. Copy ONLY %s to the client for --cert pinning.\n' "$crt"
