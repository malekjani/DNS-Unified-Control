#!/usr/bin/env bash
# Hard gate: a successful bootstrap is not proof that the dashboard is usable.
set -Eeuo pipefail
fail() {
  echo "ERROR: local runtime health failed: $*" >&2
  systemctl show dns-unified-web.service -p ActiveState -p Result -p ExecMainStatus >&2 || true
  journalctl -u dns-unified-web.service -n 18 --no-pager >&2 || true
  exit 1
}
systemctl is-active --quiet dns-unified-agent.socket || fail 'Agent socket is not active'
ready=0
for attempt in {1..15}; do
  if systemctl is-active --quiet dns-unified-web.service; then
    status=$(curl --noproxy '*' -sS -o /dev/null -w '%{http_code}' \
      --connect-timeout 2 --max-time 3 http://127.0.0.1:8088/ 2>/dev/null || true)
    if [[ "$status" =~ ^[234][0-9][0-9]$ ]]; then
      ready=1; break
    fi
  fi
  sleep 0.5
done
(( ready == 1 )) || fail 'Web service did not answer HTTP on 127.0.0.1:8088'
echo "Local readiness: Agent=ACTIVE; Web=HTTP_${status}"
