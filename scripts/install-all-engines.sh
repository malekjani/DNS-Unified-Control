#!/usr/bin/env bash
# Compatibility entrypoint: centralized, resumable installer. No duplicate logic.
set -Eeuo pipefail
[[ $EUID == 0 ]] || { echo 'Run as root' >&2; exit 1; }
exec env PYTHONPATH=/opt/dns-unified-control /opt/dns-unified-control/.venv/bin/python -m duc.provision "$@"
