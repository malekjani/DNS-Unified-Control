#!/usr/bin/env bash
# Optional one-command SSH-to-SOCKS5 migration. Uses DUC's Exclusive Mode manager.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run as root on VPS' >&2; exit 1; }
PY=/opt/dns-unified-control/.venv/bin/python
[[ -x "$PY" ]] || { echo 'DUC is not installed in /opt/dns-unified-control' >&2; exit 1; }
export PYTHONPATH=/opt/dns-unified-control
if [[ ${1:-} == --ssh ]]; then
  "$PY" -m duc.dante ssh
elif [[ $# -eq 0 ]]; then
  "$PY" -m duc.dante install
  "$PY" -m duc.dante activate
else
  echo 'Usage: bash setup-dante-backend.sh [--ssh]' >&2
  exit 2
fi
"$PY" -m duc.dante status
echo 'For your private v2rayN SOCKS URI (DO NOT POST IT):'
echo '  PYTHONPATH=/opt/dns-unified-control /opt/dns-unified-control/.venv/bin/python -m duc.dante credentials'
echo 'The DUC-managed DNS engine and UDP port 53 remain under Exclusive Mode.'
