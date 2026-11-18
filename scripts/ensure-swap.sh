#!/usr/bin/env bash
# Optional one-time 2 GiB swap preparation on low-memory VPS hosts.
# Only run after interactive administrator approval in fresh-install.sh.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo 'Root required' >&2; exit 1; }
[[ "${1:-}" == '--create' ]] || { echo 'Usage: sudo bash scripts/ensure-swap.sh --create' >&2; exit 2; }
path=/swapfile
if [[ -n "$(swapon --noheadings --show=NAME)" ]]; then
  echo 'Swap already active; leaving unchanged.'
  exit 0
fi
if [[ -e "$path" || -L "$path" ]]; then
  echo '/swapfile exists but is not active. Refusing to overwrite existing data.' >&2
  exit 2
fi
free_kib=$(df -Pk / | awk 'NR==2 {print $4}')
[[ "$free_kib" =~ ^[0-9]+$ && "$free_kib" -gt 4194304 ]] || {
  echo 'At least 4 GiB free required to create 2 GiB swap safely.' >&2; exit 2;
}
umask 077
if ! fallocate -l 2G "$path"; then
  rm -f -- "$path"
  dd if=/dev/zero of="$path" bs=1M count=2048 status=none
fi
chmod 0600 "$path"
if ! mkswap "$path" >/dev/null; then
  rm -f -- "$path"
  exit 1
fi
if ! swapon "$path"; then
  echo 'Could not activate swap. File preserved for administrator inspection.' >&2
  exit 1
fi
if ! grep -Eq '^[[:space:]]*/swapfile[[:space:]]+none[[:space:]]+swap[[:space:]]' /etc/fstab; then
  printf '%s\n' '/swapfile none swap sw 0 0' >> /etc/fstab
fi
echo '2 GiB swap enabled and configured to survive reboot.'
