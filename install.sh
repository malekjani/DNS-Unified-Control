#!/usr/bin/env bash
set -Eeuo pipefail
# Single public entrypoint. Internal application deployment is only called
# by the reviewed lifecycle stages (fresh/upgrade/repair).
cd "$(dirname "${BASH_SOURCE[0]}")"
if [[ "${DUC_INTERNAL_INSTALL:-0}" != 1 ]]; then
  # Every public invocation checks the extracted release payload first.
  python3 scripts/verify-release.py
  exec python3 -m duc.lifecycle "$@"
fi
if [[ $EUID -ne 0 ]]; then echo 'Run as root (sudo bash install.sh)' >&2; exit 1; fi
if [[ ! -f ./duc/web.py || ! -f ./deploy/dns-unified-agent.socket ]]; then echo 'Run this script from the extracted project folder' >&2; exit 1; fi
command -v systemctl >/dev/null || { echo 'systemd required'; exit 1; }
command -v apt-get >/dev/null || { echo 'Installer currently supports Debian/Ubuntu apt; see README for others'; exit 1; }
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-venv python3-pip iproute2 bind9-dnsutils
if ! getent group dns-unified >/dev/null; then groupadd --system dns-unified; fi
if ! id dns-unified >/dev/null 2>&1; then useradd --system --gid dns-unified --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin dns-unified; fi
install -d -m 0755 /opt/dns-unified-control
cp -R ./duc ./web ./scripts ./client ./docs ./soar-src ./requirements.txt ./VERSION /opt/dns-unified-control/
cp -R ./ducmulti /opt/dns-unified-control/
chown -R root:root /opt/dns-unified-control/duc /opt/dns-unified-control/ducmulti /opt/dns-unified-control/web /opt/dns-unified-control/client /opt/dns-unified-control/docs /opt/dns-unified-control/soar-src /opt/dns-unified-control/requirements.txt
python3 -m venv /opt/dns-unified-control/.venv
/opt/dns-unified-control/.venv/bin/pip install --disable-pip-version-check -r /opt/dns-unified-control/requirements.txt
# IMPORTANT: guided installer uses umask 077 to protect instance secrets;
# without an explicit group-access repair this makes .venv 0700 and systemd
# fails with status=203/EXEC before Uvicorn can start.
bash ./scripts/ensure-runtime-access.sh
install -d -m 0750 -o root -g dns-unified /etc/dns-unified
install -d -m 0700 /etc/dns-unified/keys /etc/dns-unified/engines /etc/dns-unified/engines/master /etc/dns-unified/engines/dns2tcp /etc/dns-unified/engines/xdns
install -d -m 0710 -o root -g dns-unified /var/lib/dns-unified
# TOTP state is writable only by the unprivileged panel service and root.
install -d -m 0700 -o dns-unified -g dns-unified /var/lib/dns-unified/mfa
if [[ -f /var/lib/dns-unified/mfa/web-mfa.json ]]; then
  chown dns-unified:dns-unified /var/lib/dns-unified/mfa/web-mfa.json
  chmod 0600 /var/lib/dns-unified/mfa/web-mfa.json
fi
# Multi-Engine units are deployed but NOT started, enabled or switched here.
for file in dns-unified-agent.socket dns-unified-agent.service dns-unified-web.service dns-unified@.service dns-unified-multi@.service dns-unified-multi-router.service;do install -m 0644 "./deploy/$file" "/etc/systemd/system/$file";done
if [[ ! -f /etc/dns-unified/web-auth.json ]];then
  /opt/dns-unified-control/.venv/bin/python -m duc.set_password
else
  echo 'Preserving existing admin password. To change it: sudo /opt/dns-unified-control/.venv/bin/python -m duc.set_password'
fi
systemctl daemon-reload
# Permit retry after an earlier 203/EXEC exhausted systemd's start limit.
systemctl reset-failed dns-unified-web.service 2>/dev/null || true
systemctl enable --now dns-unified-agent.socket dns-unified-web.service
# On upgrades, reload the already-running Python services to pick up new source.
# Never restart a running tunnel engine during panel upgrade.
systemctl try-restart dns-unified-agent.service
systemctl restart dns-unified-web.service
# Installation must never say success merely because systemd accepted Start.
bash ./scripts/check-local-health.sh
if [[ -t 0 && ${DUC_SKIP_WIZARD:-0} != 1 ]]; then
  source ./scripts/confirm-yes-no.sh
  if duc_confirm_yes_no 'Configure Cloudflare DNS delegation now?'; then
    env PYTHONPATH=/opt/dns-unified-control /opt/dns-unified-control/.venv/bin/python -m duc.cloudflare_dns || echo 'Cloudflare DNS setup incomplete; retry with: sudo env PYTHONPATH=/opt/dns-unified-control /opt/dns-unified-control/.venv/bin/python -m duc.cloudflare_dns'
  fi
fi
if [[ -t 0 && ${DUC_SKIP_WIZARD:-0} != 1 ]] && [[ ! -f /etc/systemd/system/dns-unified-web.service.d/https.conf ]]; then
  source ./scripts/confirm-yes-no.sh
  if duc_confirm_yes_no 'Enable public HTTPS for the management panel (requires public TCP 80/443)?'; then
    bash ./scripts/setup-panel-https.sh || echo 'HTTPS setup incomplete; retry: sudo bash scripts/setup-panel-https.sh'
  fi
fi
# Soar server is a MANDATORY install/upgrade stage, regardless of the optional
# "install every engine" wizard. It does NOT start Soar or change UDP/53.
# Failure is fatal for this installer run (but leaves existing panel/tunnel up).
# The panel remains responsible for client build/download and engine activation.
# Upgrades/recovery of the panel must not rebuild unrequested third-party
# engines or regenerate their identities. Fresh installs keep existing bootstrap.
if [[ ${DUC_LIFECYCLE_SKIP_PROVISION:-0} != 1 ]]; then
printf '\n=== Soar server auto-provision: binary + Ed25519 keys ===\n'
if ! env PYTHONPATH=/opt/dns-unified-control /opt/dns-unified-control/.venv/bin/python -m duc.install_soar; then
  echo 'ERROR: Soar server bootstrap incomplete. Existing DNS tunnel has not been switched.' >&2
  echo 'Review the preceding error; retry this installer after fixing toolchain/network/source access.' >&2
  exit 1
fi
printf '=== Soar server assets verified; no DNS engine activated ===\n'

# Mandatory NoizDNS server stage, separate from any optional client build.
# Builds the reviewed anonvector/dnstt fork as a DISTINCT noizdns-server binary,
# creates/preserves Noise identity, migrates the old default SSH target to Dante.
# Exclusive Mode remains untouched (no DNS/53 service start or restart).
printf '\n=== NoizDNS server auto-provision: binary + Noise keys + Dante backend ===\n'
if ! env PYTHONPATH=/opt/dns-unified-control /opt/dns-unified-control/.venv/bin/python -m duc.install_noizdns; then
  echo 'ERROR: NoizDNS server bootstrap incomplete. Existing DNS tunnel has not been switched.' >&2
  exit 1
fi
printf '=== NoizDNS server assets verified; no DNS engine activated ===\n'
else
  echo 'Lifecycle maintenance: preserving installed engine binaries/keys; skipping upstream builds.'
fi
if [[ ${DUC_INSTALL_ENGINES:-0} == 1 ]];then
  echo 'Resuming missing engine installations with the unified provisioner.'
  bash ./scripts/install-all-engines.sh || echo 'Some engines require attention; inspect /var/lib/dns-unified/provision-report.json.'
elif [[ -t 0 && ${DUC_SKIP_WIZARD:-0} != 1 ]];then
  source ./scripts/confirm-yes-no.sh
  if duc_confirm_yes_no 'Install all upstream DNS engines now? This builds third-party source (review first).'; then
    bash ./scripts/install-all-engines.sh || echo 'Partial install; inspect /var/lib/dns-unified/provision-report.json.'
  fi
fi
printf '\nInstalled. Local admin (SSH forwarding):\n  ssh -L 8088:127.0.0.1:8088 user@YOUR_VPS\n  http://127.0.0.1:8088\nWeb installation is INCOMPLETE until certificate, renewal, HTTPS routing and panel DNS are verified by lifecycle.\nEngine installation status must be checked separately. See README.md.\n'
