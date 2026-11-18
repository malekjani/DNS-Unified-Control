#!/usr/bin/env bash
# Source this file for human confirmation. Only literal yes (case-insensitive)
# approves; no, blank, EOF and unrecognized input deny the change.
duc_confirm_yes_no() {
  local answer
  if ! IFS= read -r -p "$1 [yes/no] (default: no): " answer; then
    echo 'Cancelled: no confirmation provided.' >&2
    return 1
  fi
  answer="${answer,,}"
  if [[ "$answer" == 'yes' ]]; then return 0; fi
  if [[ "$answer" != 'no' && -n "$answer" ]]; then
    echo "Invalid reply: only yes/no accepted; no changes authorized." >&2
  fi
  return 1
}
