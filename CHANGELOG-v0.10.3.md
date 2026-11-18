# v0.10.3 — Lifecycle Manager (no new engines)

- Single public `sudo bash install.sh` with source integrity verification and read-only mode detection.
- Automatically selects fresh / resume / upgrade / repair; refuses downgrade, instance mismatch and concurrent lifecycle operations.
- Root-only atomic checkpoint journal for resumable actions, with error kind and stage only (no secrets).
- Upgrades snapshot application code + systemd service units before apply, and attempt scoped rollback on failure.
- Non-destructive repair of runtime permissions / Web launch; real Agent API, HTTP and Dante health gates.
- Public HTTPS status tracked independently of local readiness; no Cloudflare writes or DNS/53 activation.
- Legacy `fresh-install.sh` and `upgrade.sh` remain read-only/compatibility frontends; no duplicate public installers.
- Optional provisioner remains opt-in; upgrade no longer rebuilds mandatory engine code.

**Not promised:** fully transactional package rollback, encrypted secret backups, automated TLS DNS-01, or real VPS field tests.

Full operational guide: `docs/LIFECYCLE_V0103_FA.md`.
