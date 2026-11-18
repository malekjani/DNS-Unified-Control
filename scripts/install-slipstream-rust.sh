#!/usr/bin/env bash
# Compatibility entrypoint. Retired the archived Mygod source-build installer.
# The only supported path is the consent-gated AliRezaBeigy release importer.
set -Eeuo pipefail
printf '%s\n' 'Legacy Rust source build has been retired for this project.' \
 'Use: bash /opt/dns-unified-control/scripts/install-slipstream-ali.sh' >&2
exec bash /opt/dns-unified-control/scripts/install-slipstream-ali.sh "$@"
