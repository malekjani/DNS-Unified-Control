#!/usr/bin/env bash
# DNS Unified TUI: use the installed application directory, not caller's cwd.
# No daemon, gateway, privileged shell command or additional network listener.
set -Eeuo pipefail
BASE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
[[ -x "$BASE/.venv/bin/python" ]] || { echo 'Python venv not found; complete install/upgrade first' >&2; exit 1; }
cd "$BASE"
exec "$BASE/.venv/bin/python" -m duc.tui "$@"
