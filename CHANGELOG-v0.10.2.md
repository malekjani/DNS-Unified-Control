# v0.10.2 — Web Runtime Permissions & Honest Install Readiness

- Fix first-run `systemd` `203/EXEC: Permission denied` triggered by `umask 077` protecting instance secrets. Explicitly grant read/traverse/execute to `dns-unified` group **inside `/opt/dns-unified-control` only**, keep the tree non-writable for the service, and validate execution as the unprivileged account.
- Web startup now has a real local HTTP + Agent socket readiness gate; a broken web service fails installation instead of printing a misleading `BASE INSTALLED` result.
- `--postcheck` checks actual HTTP readiness and propagates failures.
- New read-only `scripts/panel-https-status.sh` distinguishes local HTTP readiness, validated TLS, and deferred HTTPS. The wizard explains why migrations require approved panel DNS cutover for HTTP-01 or a separate DNS-01 challenge.
- No Cloudflare writes, no DNS-engine activation, no key rotation, and no Dante restart from the new checks.
- Does not implement DNS-01 issuance or a full transactional/automatic rollback of third-party package installs.
