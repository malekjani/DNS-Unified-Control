#!/usr/bin/env bash
set -u
printf '%s\n' '=== DNS Unified v0.4 diagnostic (no secrets) ==='
for name in dns-unified-agent.socket dns-unified-web.service;do
  printf '%-36s' "$name";systemctl is-active "$name" 2>/dev/null || true
done
printf '\n=== Port 53 and panel listen sockets ===\n'
ss -lntup 2>/dev/null | grep -E ':53([[:space:]]|$)|:8088([[:space:]]|$)' || true
printf '\n=== Engine systemd and executable ===\n'
for line in 'master masterdnsvpn-server' 'slipstream slipstream-rust-server' 'dnstt dnstt-server' 'noizdns noizdns-server' 'vaydns vaydns-server' 'soar duc-soar-server' 'iodine iodined' 'dns2tcp dns2tcpd' 'xdns xray';do
  read -r eng binary <<< "$line"
  state=$(systemctl is-active "dns-unified@$eng.service" 2>/dev/null || true)
  executable=$(command -v "$binary" 2>/dev/null || true)
  printf '%-12s systemd=%-12s binary=%s\n' "$eng" "$state" "${executable:-MISSING}"
done
printf '\n=== DNS delegation verification (optional, with dig) ===\n'
if command -v dig >/dev/null;then
  if [[ -f /etc/dns-unified/profiles.json ]];then
    python3 - <<'PY' | while read -r engine fqdn;do
import json
from pathlib import Path
profiles=json.loads(Path('/etc/dns-unified/profiles.json').read_text())
for e,c in profiles.items():print(e,c.get('domain',''))
PY
    [[ -z "$fqdn" ]] && continue
    result=$(dig +time=2 +tries=1 +short NS "$fqdn" @1.1.1.1 2>/dev/null | tr '\n' ' ')
    printf '%-12s %-38s NS=%s\n' "$engine" "$fqdn" "${result:-NO RESPONSE}"
  done
  else echo 'No profiles yet; first configure Cloudflare and profiles';fi
else echo 'Install bind9-dnsutils for remote recursive resolver delegation tests';fi
printf '\n=== Security ===\nDo not post keys, client tokens, or the web admin password. No end-to-end client test is included.\n'
