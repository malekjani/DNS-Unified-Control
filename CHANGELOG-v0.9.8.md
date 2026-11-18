# v0.9.8 — Readiness & Local TUI

See docs/TUI_V098_FA.md.

- Readiness status is not a claim of live DNS or SOCKS success.
- The UI/CLI calls Agent routes over the Unix socket; systemd changes remain in core.switch.
- Web access to readiness requires existing login + MFA.
- Requires Linux server-local access; no network service or additional daemon.
