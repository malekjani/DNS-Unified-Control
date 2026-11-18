#!/usr/bin/env bash
# Make application code and Python environment readable/executable by the
# unprivileged web service, without exposing secrets under /etc or /var/lib.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo 'Root required for runtime permissions' >&2; exit 1; }
APP_ROOT=/opt/dns-unified-control
[[ -d "$APP_ROOT/.venv" ]] || { echo 'Python environment missing' >&2; exit 1; }
getent group dns-unified >/dev/null || { echo 'Service group missing' >&2; exit 1; }
# The app directory contains only distributable source and dependency files.
# Keys, passwords and MFA live outside this directory, with private ACLs.
chown root:dns-unified "$APP_ROOT"
chmod 0750 "$APP_ROOT"
for name in .venv duc web scripts client docs soar-src; do
  [[ -e "$APP_ROOT/$name" ]] || continue
  chgrp -R dns-unified "$APP_ROOT/$name"
  chmod -R g+rX,g-w "$APP_ROOT/$name"
done
# Venv generated with umask=077 often has 0700 folders. Validate via the
# real service UID; root's executable test would miss this regression.
runuser -u dns-unified -- "$APP_ROOT/.venv/bin/uvicorn" --version >/dev/null || {
  echo 'Web service UID cannot execute uvicorn; inspect namei -l on its path' >&2
  exit 1
}
echo 'Web runtime permissions verified as dns-unified (no secret paths modified).'
