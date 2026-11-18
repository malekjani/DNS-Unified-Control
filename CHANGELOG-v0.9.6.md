# DNS Unified Control v0.9.6 — Client Choice / Dante Separation / TUI-ready Registry

- New clear navigation: engine control, engine profiles, clients, protocol catalog; separated Dante, DNS, provisioning and monitoring.
- Shared backend capability registry (`duc/client_catalog.py`) consumed by a stable JSON API usable by Web now and a future TUI.
- Two independent client variants for three engines, explicitly labelled by compatibility/field-test status:
  * DNSTT: native client (primary); pinned SlipNet DNSTT (alternative).
  * NoizDNS: pinned SlipNet sayedns Stealth (primary); standard native DNSTT-compatible client without Stealth (alternative).
  * VayDNS: native client (primary); pinned SlipNet VayDNS (alternative, field verification required).
- Independent queued systemd job `build-alternate` and authenticated downloads; never overwrites the original native artifact and never starts/swaps the DNS engine.
- SlipNet NoizDNS launch now **always** applies the chosen public recursive resolver via `--dns`, preventing the previously observed auto-direct fallback. The script supports optional `DUC_DNS_RESOLVER` and `DUC_CLIENT_PORT`.
- Separate Dante page for health, attach/restore/custom loopback, and installation. No credentials in API or packages, no extra client gateway.
- Keep current Exclusive Mode, account/MFA, existing server profiles/keys, Caddy and active DNS service unchanged across upgrade.
- 129 Python tests including new client variants and shell script validation, plus a mock-fed Chromium render of Web pages without JS errors.
- No live VPS upgrade performed. New alternative SlipNet DNSTT/VayDNS builds are **not yet** field-verified. Windows builds and a working TUI are future work.

See `docs/UI_TUI_ARCHITECTURE_V096_FA.md`.

- Canonical Dante job is now `setup-dante/dante`; legacy `install-dante/slipstream` remains valid. Older completed NoizDNS client ZIPs show `stale` and require rebuild so the explicit Resolver launcher is not bypassed.
