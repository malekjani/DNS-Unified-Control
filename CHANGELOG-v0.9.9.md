# v0.9.9 — Fresh VPS Assessor and France-first installer

- New **read-only preflight** `python3 -m duc.fresh_setup audit [--json] [--gate]`, independent of web, TUI and optional dependencies.
- New `scripts/fresh-install.sh --audit / --install / --postcheck`, with explicit fresh-install confirmation, safe resume, and no automatic DNS changes or UDP/53 service start.
- Fresh setup installs only one shared authenticated Dante and uses existing Soar/NoizDNS provisioners; other engines are opt-in.
- Initialize domains locally to `m/r/d/n/v/s/i/c/x.m2m.diy`, with safeguards against overwriting nondefault profiles.
- Include previously developed Cloudflare cutover tool for **explicit** staged panel/ns record migration and rollback.
- New Persian runbook with fresh-key incompatibility warning and planned phases for Caddy, MFA, client build, cutover and rollback.
- Regression tests of preflight and policy invariants. Tested in source environment only, not on a live VPS.
