#!/usr/bin/env bash
# Fixed-source, zero-independent-management SlipStream importer; explicit command = consent.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run as root' >&2; exit 1; }
[[ $(uname -m) == x86_64 ]] || { echo 'This pinned release supports x86_64 here only' >&2; exit 1; }
[[ -x /opt/dns-unified-control/.venv/bin/python ]] || { echo 'Upgrade panel code first' >&2; exit 1; }
for program in awk df free systemctl nproc curl openssl;do
 command -v "$program" >/dev/null || { echo "Missing $program" >&2; exit 1; }
done
MIB(){ awk -v k="$1" 'BEGIN{printf "%.0f",k/1024}'; }
ram_total=$(awk '/^MemTotal:/{print $2}' /proc/meminfo)
ram_avail=$(awk '/^MemAvailable:/{print $2}' /proc/meminfo)
swap_total=$(awk '/^SwapTotal:/{print $2}' /proc/meminfo)
disk_free=$(df -Pk /usr/local/bin | awk 'NR==2{print $4}')
printf '\n== DUC SlipStream AliRezaBeigy Release Preflight ==\n'
printf 'CPU: %s cores | RAM: %s MiB total, %s MiB available | Swap: %s MiB | Disk free: %s MiB\n' \
 "$(nproc)" "$(MIB "$ram_total")" "$(MIB "$ram_avail")" "$(MIB "$swap_total")" "$(MIB "$disk_free")"
echo 'Current running DNS engine:'
systemctl list-units --type=service --state=running 'dns-unified@*.service' --no-legend --no-pager || true
if ((disk_free < 350*1024)); then
 echo 'BLOCKED: less than 350 MiB free disk.' >&2;exit 1
fi
if ((ram_total < 2*1024*1024 || ram_avail < 700*1024 || $(nproc) < 2)); then
 echo 'ASSESSMENT: Limited VPS; source compilation NOT recommended. Use 2 pinned prebuilt binaries.'
else
 echo 'ASSESSMENT: Resources adequate for prebuilt binaries; no Rust build necessary.'
fi
if ((swap_total < 512*1024));then echo 'WARNING: low swap';fi
printf '%s\n' \
 'Release: AliRezaBeigy/slipstream-rust-deploy tag 42e3e75' \
 'Source: https://github.com/AliRezaBeigy/slipstream-rust-deploy/releases/tag/42e3e75' \
 'Checks: pinned SHA-256 of BOTH server and client; ELF64 x86_64 and CLI flags' \
 'Preserves: iodine/other active engine; existing DNS profiles and TLS; Caddy; port 53' \
 'DOES NOT: execute upstream deploy script; create standalone service, Dante/SS or NAT rules.'
printf '\nStarting requested SlipStream installation (no extra yes prompt).\n'
PYTHONPATH=/opt/dns-unified-control \
 /opt/dns-unified-control/.venv/bin/python -m duc.slipstream_ali --install
