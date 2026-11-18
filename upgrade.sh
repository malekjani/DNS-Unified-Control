#!/usr/bin/env bash
# Upgrade panel safely. Preserve passwords, TOTP, profiles, Cloudflare DNS, Caddy,
# keys, and running tunnel engine; Soar and NoizDNS server assets are auto-provisioned.
# Other engines remain opt-in; no engine or Dante service is started/restarted.
set -Eeuo pipefail
# Backward compatible alias: public users only need sudo bash install.sh.
# The legacy upgrade routine is restricted to deliberate internal usage.
if [[ ${DUC_LIFECYCLE_INTERNAL_UPGRADE:-0} != 1 ]]; then
  if (( $# )); then
    echo 'The legacy --install-missing option is separate from lifecycle. Run install.sh for upgrade, then scripts/install-all-engines.sh explicitly.' >&2
    exit 2
  fi
  echo 'upgrade.sh is deprecated; routing through Lifecycle Manager.' >&2
  exec bash "$(dirname "${BASH_SOURCE[0]}")/install.sh"
fi
[[ $EUID -eq 0 ]] || { echo 'Run as root' >&2; exit 1; }
[[ -f ./install.sh && -f ./duc/web.py ]] || { echo 'Run from extracted project directory' >&2; exit 1; }
if [[ ${1:-} != '' && ${1:-} != --install-missing ]]; then echo 'Usage: bash upgrade.sh [--install-missing [--include-heavy]]' >&2; exit 2; fi
if [[ -d /opt/dns-unified-control ]];then
  BACKUP="/root/duc-panel-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
  # Pre-v0.8 installs did not copy client/ or docs/ into /opt: archive only
  # existing locations so upgrades from v0.7 never abort during backup.
  BACKUP_ITEMS=()
  for name in duc web scripts client docs soar-src; do
    [[ -e "/opt/dns-unified-control/$name" ]] && BACKUP_ITEMS+=("dns-unified-control/$name")
  done
  if (( ${#BACKUP_ITEMS[@]} )); then
    tar -C /opt -czf "$BACKUP" "${BACKUP_ITEMS[@]}"
  else
    echo "No source directories found to back up; refusing upgrade" >&2
    exit 1
  fi
  chmod 0600 "$BACKUP"
  echo "Code backup: $BACKUP"
fi
# install.sh automatically installs/verifies Soar and NoizDNS servers and keys.
# No separate web-panel server installer action is necessary for either.
export DUC_INTERNAL_INSTALL=1
DUC_SKIP_WIZARD=1 DUC_INSTALL_ENGINES=0 bash ./install.sh
# Deprecated gateway *files* (not active services) are removed only after the source backup.
# v0.9 uses each tunnel client directly on port 2080; no local gateway is installed.
rm -f /opt/dns-unified-control/client/duc_socks_gateway.py /opt/dns-unified-control/client/install-user.sh
# Opt-in batch, resumable provisioning; never stop the running DNS engine.
if [[ ${1:-} == --install-missing ]]; then
  shift
  bash ./scripts/install-all-engines.sh "$@"
elif [[ $# -gt 0 ]]; then
  echo "Usage: bash upgrade.sh [--install-missing [--include-heavy]]" >&2
  exit 2
fi
printf '\nUpgrade completed. Existing tunnel engine was not restarted.\n'
echo 'Verify: systemctl is-active dns-unified-web dns-unified-agent.socket'
if [[ -f /etc/dns-unified/instance.json ]]; then
  echo 'Instance: '
  env PYTHONPATH=/opt/dns-unified-control /opt/dns-unified-control/.venv/bin/python -m duc.instance show --field panel_fqdn || true
else
  echo 'Legacy install: no instance identity recorded; inspect existing domain settings before future migration.'
fi
