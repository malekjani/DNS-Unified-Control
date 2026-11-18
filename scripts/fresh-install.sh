#!/usr/bin/env bash
# Product fresh VPS setup. Does not mutate Cloudflare records or activate UDP/53 engines.
# Complete guided cutover is a separate reviewed operation.
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source ./scripts/confirm-yes-no.sh
# Compatibility-only diagnostic entrypoint. All mutating fresh/resume/upgrade
# operations go through the durable Lifecycle Manager in top-level install.sh.
if [[ "${DUC_LIFECYCLE_LEGACY_INTERNAL:-0}" != 1 ]]; then
  READ_ONLY=0
  for arg in "$@"; do
    case "$arg" in --audit|--postcheck) READ_ONLY=1;; esac
  done
  if (( READ_ONLY == 0 )); then
    echo 'Old fresh installer is deprecated. Starting unified Lifecycle Manager.' >&2
    echo 'Any former --domain/--ip options will be requested safely by the guided installer.' >&2
    exec bash ./install.sh
  fi
fi
usage() {
  cat <<'EOF'
Usage:
  sudo bash scripts/fresh-install.sh            # recommended: audit -> guided installation
  sudo bash scripts/fresh-install.sh --guided [--domain DOMAIN] [--ip PUBLIC_IPV4]
  bash scripts/fresh-install.sh --audit [--domain YOUR_DOMAIN] [--ip PUBLIC_IPV4]
  sudo bash scripts/fresh-install.sh --install [--domain YOUR_DOMAIN] [--ip PUBLIC_IPV4] [--with-engines] [--resume]
  sudo bash scripts/fresh-install.sh --postcheck [--domain YOUR_DOMAIN] [--ip PUBLIC_IPV4]
Fresh install creates DIFFERENT keys/Dante credentials/TOTP than old VPS.
Never change existing public NS records until new clients are tested.
EOF
}
ACTION='' DOMAIN='' IP='' WITH_ENGINES=0 RESUME=0 WANT_SWAP=0
while (( $# )); do
  case "$1" in
    --audit|--install|--postcheck|--guided) [[ -z "$ACTION" ]] || { usage >&2; exit 2; }; ACTION="$1";;
    --domain) [[ $# -ge 2 ]] || exit 2; DOMAIN="$2"; shift;;
    --ip) [[ $# -ge 2 ]] || exit 2; IP="$2"; shift;;
    --with-engines) WITH_ENGINES=1;;
    --resume) RESUME=1;;
    --help|-h) usage; exit 0;;
    *) usage >&2; exit 2;;
  esac
  shift
done
[[ -n "$ACTION" ]] || ACTION=--guided
[[ -f ./duc/fresh_setup.py && -f ./install.sh ]] || { echo 'Project source not found' >&2; exit 2; }
command -v python3 >/dev/null || { echo 'python3 required for assessment' >&2; exit 2; }
args=()
[[ -z "$DOMAIN" ]] || args+=(--domain "$DOMAIN")
[[ -z "$IP" ]] || args+=(--ip "$IP")
(( RESUME == 0 )) || args+=(--resume)
if [[ "$ACTION" == --audit ]]; then
  exec python3 -m duc.fresh_setup audit "${args[@]}"
fi
if [[ "$ACTION" == --guided ]]; then
  [[ $EUID -eq 0 ]] || { echo 'Guided installation requires root. Use sudo bash scripts/fresh-install.sh' >&2; exit 1; }
  [[ -t 0 ]] || { echo 'Guided installation requires an interactive SSH terminal.' >&2; exit 1; }
  echo '=== DNS UNIFIED CONTROL: GUIDED FIRST INSTALL ==='
  echo '[0/6] Read-only server assessment (no domain, IP or token required)'
  # Unsupported OS, existing live installations, missing systemd or low disk
  # stop the process BEFORE collecting any credentials or mutating the host.
  if ! python3 -m duc.fresh_setup audit "${args[@]}" --gate; then
    echo 'Blocking conflict detected. Nothing was installed or changed.' >&2
    echo 'Fix blocking checks and run the same command again.' >&2
    exit 2
  fi
  echo
  echo '[1/6] Instance domain (DNS is NOT changed during installation)'
  while :; do
    if [[ -z "$DOMAIN" ]]; then
      read -r -p 'Your base domain (e.g. example.com): ' DOMAIN
    else
      echo "Domain: $DOMAIN"
    fi
    if python3 -c 'import sys; from duc.fresh_setup import valid_domain; valid_domain(sys.argv[1])' "$DOMAIN" >/dev/null 2>&1; then
      DOMAIN="${DOMAIN,,}"; DOMAIN="${DOMAIN%.}"; break
    fi
    echo 'Invalid domain. Please enter a fully qualified domain.' >&2
    DOMAIN=''
  done
  echo
  echo '[2/6] Public IPv4: use the provider public address, NOT the local/private ens5 address.'
  while :; do
    if [[ -z "$IP" ]]; then
      read -r -p 'Public IPv4 of this VPS: ' IP
    else
      echo "Public IP: $IP"
    fi
    if python3 -c 'import sys; from duc.fresh_setup import valid_public_ip; valid_public_ip(sys.argv[1])' "$IP" >/dev/null 2>&1; then
      break
    fi
    echo 'Invalid public IPv4; private, link-local and reserved ranges are not accepted.' >&2
    IP=''
  done
  echo
  echo '[3/6] DNS provider access (read-only, optional)'
  echo 'Cloudflare token is NEVER saved and DNS records are NEVER edited during this installation.'
  if duc_confirm_yes_no 'Check Cloudflare token access to this zone now?'; then
    while ! python3 -m duc.guided_setup verify-cloudflare --domain "$DOMAIN"; do
      if duc_confirm_yes_no 'Cloudflare check failed. Retry token validation?'; then
        continue
      fi
      echo 'Skipping Cloudflare verification (DNS remains unchanged).'
      break
    done
  else
    echo 'Cloudflare verification skipped; token will be requested again for a later guarded DNS cutover.'
  fi
  echo
  echo 'HTTPS / certificate: deferred while existing panel DNS points to another server.'
  echo 'Certificate issuance via HTTP-01 requires approved panel DNS cutover and access to TCP/80 or 443.'
  echo 'Pre-cutover issuance requires separately configured DNS-01; the read-only Cloudflare token check is NOT sufficient.'
  echo
  echo '[4/6] Resources and optional repair'
  swap_kib=$(awk '/^SwapTotal:/ {print $2}' /proc/meminfo)
  mem_kib=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
  if [[ "${swap_kib:-0}" -eq 0 && "${mem_kib:-0}" -lt 1572864 ]]; then
    echo 'Low-memory VPS with no swap detected. 2 GiB swap is recommended for engine compilation.'
    if duc_confirm_yes_no 'Create /swapfile (2 GiB) after final confirmation?'; then WANT_SWAP=1; fi
  fi
  echo 'Existing loopback DNS stubs are NOT disabled automatically; resolve before enabling UDP/53.'
  echo
  echo '[5/6] Optional engine installation'
  if (( WITH_ENGINES == 0 )); then
    if duc_confirm_yes_no 'Build additional supported DNS engines now? Heavy on RAM/disk.'; then WITH_ENGINES=1; fi
  fi
  echo
  echo '[6/6] Re-assess with validated instance settings'
  args=(--domain "$DOMAIN" --ip "$IP")
  (( RESUME == 0 )) || args+=(--resume)
  python3 -m duc.fresh_setup audit "${args[@]}" --gate || exit 2
  printf '\nReview: domain=%s; public IP=%s; extra engines=%s; create swap=%s; Cloudflare untouched; DNS engine stays OFF.\n' "$DOMAIN" "$IP" "$WITH_ENGINES" "$WANT_SWAP"
  ACTION=--install
fi
[[ -n "$DOMAIN" ]] || { usage >&2; exit 2; }
args=(--domain "$DOMAIN")
[[ -z "$IP" ]] || args+=(--ip "$IP")
(( RESUME == 0 )) || args+=(--resume)
if [[ "$ACTION" == --postcheck ]]; then
  [[ $EUID -eq 0 ]] || { echo 'Run as root' >&2; exit 1; }
  instance_args=(--domain "$DOMAIN")
  [[ -z "$IP" ]] || instance_args+=(--ip "$IP")
  python3 -m duc.instance verify "${instance_args[@]}" || { echo 'Instance identity mismatch; refusing postcheck.' >&2; exit 2; }
  echo '=== Engine / Dante / panel readiness (read-only) ==='
  bash ./scripts/check-local-health.sh
  env PYTHONPATH=/opt/dns-unified-control /opt/dns-unified-control/.venv/bin/python -m duc.dante status
  env PYTHONPATH=/opt/dns-unified-control /opt/dns-unified-control/.venv/bin/python -m duc.fieldcheck
  echo '=== Panel TLS / DNS status ==='
  bash ./scripts/panel-https-status.sh
  echo '=== Listen addresses ==='
  ss -lntup | grep -E '(:53|:1080|:8088|:80|:443)([[:space:]]|$)' || true
  exit 0
fi
[[ $EUID -eq 0 ]] || { echo 'Run as root (sudo bash scripts/fresh-install.sh --install ...)' >&2; exit 1; }
[[ -t 0 ]] || { echo 'A local interactive SSH terminal is required for the first admin password and confirmation.' >&2; exit 1; }
[[ -n "$IP" ]] || { echo 'Specify this VPS public IPv4 with --ip.' >&2; exit 2; }
# Guard and record an auditable, public-info-only preflight; fail on blocking errors.
python3 -m duc.fresh_setup audit "${args[@]}" --gate
umask 077
install -d -m 0700 /root/duc-fresh-reports
report="/root/duc-fresh-reports/assessment-$(date -u +%Y%m%dT%H%M%SZ).json"
python3 -m duc.fresh_setup audit "${args[@]}" --json > "$report"
chmod 0600 "$report"
printf '\nPlan: NEW installation with NEW keys and Dante. No Cloudflare writes or DNS engine activation.\n'
printf 'Preflight report: %s\n' "$report"
duc_confirm_yes_no "Begin fresh installation for $DOMAIN at $IP with new credentials?" || { echo 'Cancelled.'; exit 1; }
# Create/check the durable per-server identity before any package or service mutation.
# --resume only succeeds when domain and public IPv4 match the original install.
identity_args=(--domain "$DOMAIN" --ip "$IP")
(( RESUME == 0 )) || identity_args+=(--resume)
python3 -m duc.instance init "${identity_args[@]}"
if (( WANT_SWAP )); then
  bash ./scripts/ensure-swap.sh --create
fi
# Existing upstream installer performs apt + Python/bootstrap and provisions Soar/NoizDNS.
DUC_INTERNAL_INSTALL=1 DUC_SKIP_WIZARD=1 DUC_INSTALL_ENGINES=0 bash ./install.sh
# Keep shared Dante independent of engine services and private on loopback.
env PYTHONPATH=/opt/dns-unified-control /opt/dns-unified-control/.venv/bin/python -m duc.dante install
# Running any DNS engine during setup is forbidden; defaults map m/r/d/n/v/s/i/c/x to this domain.
env PYTHONPATH=/opt/dns-unified-control /opt/dns-unified-control/.venv/bin/python -m duc.fresh_setup profiles --domain "$DOMAIN"
if (( WITH_ENGINES )); then
  echo 'Installing additional missing supported engines (will NOT activate UDP/53).'
  # Partial failures are reported, never silently declared successful.
  bash ./scripts/install-all-engines.sh || echo 'Some engines remain uninstalled/review-required. Inspect provision-report.json.' >&2
fi
printf '\n=== Local health ===\n'
bash ./scripts/check-local-health.sh
ss -lntp | grep -E '127\.0\.0\.1:(1080|8088)([[:space:]]|$)' || true
env PYTHONPATH=/opt/dns-unified-control /opt/dns-unified-control/.venv/bin/python -m duc.dante status
printf '\n=== HTTPS readiness (separate from HTTP readiness) ===\n'
bash ./scripts/panel-https-status.sh
printf '\nBASE INSTALLED (local HTTP ready; public TLS might be deferred). Do NOT change Cloudflare yet.\n'
printf 'Next: configure MFA via SSH-forwarded web panel; build/test fresh clients; activate ONE engine via Agent.\n'
printf 'Panel certificate: issue via Caddy AFTER approved panel A cutover, or use separately configured DNS-01.\n'
printf 'After tests: guarded panel A cutover -> Caddy/TLS -> guarded ns A cutover.\n'
printf 'Keep original VPS alive for rollback. See docs/FRESH_FRANCE_FA.md.\n'
