#!/usr/bin/env bash
# Initialize key files without overwriting existing credentials.
# Runs independently of tunnel services. Safe to rerun.
set -Eeuo pipefail
[[ $EUID == 0 ]] || { echo 'sudo required' >&2; exit 2; }
KEYS=/etc/dns-unified/keys
mkdir -p "$KEYS"
chmod 0700 "$KEYS"
umask 077
# NoizDNS is provisioned and validated by install.sh/upgrade.sh (no duplicate key generator).
for name in dnstt vaydns;do
  bin="${name}-server"
  [[ -e "$KEYS/$name.key" ]] && { echo "$name: preserving existing key";continue; }
  if ! command -v "$bin" >/dev/null;then echo "$name: binary not installed";continue;fi
  if "$bin" -gen-key -privkey-file "$KEYS/$name.key" -pubkey-file "$KEYS/$name.pub" </dev/null;then
    chmod 0600 "$KEYS/$name.key";chmod 0644 "$KEYS/$name.pub"
    echo "$name: keypair created"
  else
    rm -f "$KEYS/$name.key" "$KEYS/$name.pub"
    echo "$name: keygen unsupported; follow upstream fork instructions" >&2
  fi
done
if command -v noizdns-server >/dev/null 2>&1; then
  echo 'noizdns: server keypair managed by duc.install_noizdns (install/upgrade)'
else
  echo 'noizdns: install/upgrade the panel to provision the dedicated server first'
fi
if [[ ! -e "$KEYS/soar.key" ]] && command -v duc-soar-server >/dev/null; then
  if duc-soar-server keygen 2>/dev/null | awk '$1=="private"{print $2}' >"$KEYS/soar.key" && [[ -s "$KEYS/soar.key" ]];then
    chmod 0600 "$KEYS/soar.key"
    duc-soar-server pubkey "$KEYS/soar.key" >"$KEYS/soar.pub"
    echo 'soar: keypair created'
  else rm -f "$KEYS/soar.key";echo 'soar: keygen failed' >&2;fi
fi
if [[ ! -e "$KEYS/iodine.pass" ]];then
 python3 -c 'import secrets;print(secrets.token_urlsafe(22)[:32])' >"$KEYS/iodine.pass"
 chmod 0600 "$KEYS/iodine.pass"
fi
if [[ ! -e "$KEYS/dns2tcp.key" ]];then
 python3 -c 'import secrets;print(secrets.token_urlsafe(24))' >"$KEYS/dns2tcp.key"
 chmod 0600 "$KEYS/dns2tcp.key"
fi
# MasterDnsVPN secret generation is upstream format-sensitive. Do not guess.
[[ -e "$KEYS/master.key" ]] || echo 'master: use upstream encryption-key generator; not generated here'
[[ -e "$KEYS/slipstream-rust.key" ]] || echo 'slipstream: run bundled prepare-slipstream-rust.sh'
[[ -e /etc/dns-unified/engines/xdns/server.json ]] || echo 'xdns: provide and validate Xray native FinalMask config'
echo 'Secret preparation complete; missing items remain visible in web preflight.'
