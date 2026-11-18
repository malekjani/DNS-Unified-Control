# 0.10.5 — Component-aware installation completion

- Web certificate/renewal now mandatory for completed Web installation and integrated into ordinary lifecycle flow.
- TUI readiness remains independent of Web public readiness; partial installs are accurately recorded.
- Renewal credential path is checked and can be repaired with Certbot reconfigure upon explicit consent.

v0.10.3: Unified Lifecycle Manager; fresh/resume/upgrade/repair, checkpoint journal, guarded code snapshot rollback, real Agent/Web/Dante checks. See `CHANGELOG-v0.10.3.md`.

v0.10.2: Web runtime permission 203/EXEC fix, real local readiness gate, TLS status independent of install.

## v0.10.1 — Guided first-run workflow
- Default CLI runs read-only preflight, checks port conflicts, requests per-instance settings, and installs only after explicit confirmation. See `CHANGELOG-v0.10.1.md`.

## v0.10.0 — Portable Product Foundation

- Fresh installation accepts any separately owned valid domain and public IPv4: neither is fixed in runtime code.
- Per-server identity UUID with guarded same-instance resume and safe, secret-free Web/TUI readiness display.
- Cloudflare migration requires explicit zone name, preserving existing NS records.
- OS support gate: Ubuntu 24.04 LTS, Debian 12/13 (other versions blocked until verified).
- Improved generic diagnostics and release-integrity manifest; no network side effects during audit.

## v0.9.9 (France Fresh Installer)

Read-only first-run assessment with JSON contract, new guarded installation wizard, fresh identity and clients, local domain profiles and explicit Cloudflare panel/ns cutover with rollback. See CHANGELOG-v0.9.9.md.

## 0.9.8 — Local TUI / Readiness

- Pure-stdlib local TUI/CLI using the existing privileged Unix Socket Agent.
- Read-only shared readiness endpoint for TUI and authenticated web.
- Explicit confirmation for engine switch/stop and client package jobs.
- No public ports, Dante secrets, automatic DNS engine starts, or gateway.

# Version 0.9.0

See [CHANGELOG-v0.9.0.md](CHANGELOG-v0.9.0.md) for Native SOCKS, Dante, telemetry, VayDNS and retained limitations.

## v0.8.1 — Authenticated SOCKS Link and no hand-edited JSON (2026-11-05)

- Local client Gateway now requires RFC 1929 SOCKS5 username/password; rejects no-auth clients without starting an upstream connection.
- Root-only `duc.unified export-setup /root/<file>.sh` creates a private one-time setup script (0600) containing Dante credentials and separate generated local SOCKS credentials. Transfer over SSH; executing on Debian automatically stores a protected client config, backs up any existing config privately and prints a v2rayN `socks://BASE64(user:pass)@127.0.0.1:2080#DUC-Unified` URI.
- `duc_socks_gateway.py link` reprints that URI from the local private config. The web Gateway ZIP never includes real credentials.
- No changes to server DNS Exclusive Mode, UDP 53, installed engines, Dante or firewall. A matching DNS tunnel client is still required on its configured internal port; selection is manual.

## v0.8.0 — Shared Dante + Unified SOCKS Gateway (2026-11-05)

- Added `duc.unified` to attach multiple audited TCP-forwarding DNS engines to a single authenticated loopback Dante instance; supports explicit per-engine selection, backup of original destinations, rollback on active-engine restart failure, and Exclusive Mode preservation.
- Added web management status and explicit change action with MFA/CSRF, plus download of secret-free Linux client Gateway ZIP.
- Added standard-library-only client SOCKS5 TCP CONNECT Gateway on a stable loopback port 2080. It authenticates to Dante upstream for raw-TCP engines, or routes to native Master client SOCKS without a needless chain; changes selected local engine for new connections without restarting Gateway.
- Added root-only private client configuration export (mode 0600); no Dante passwords in web status, guide bundles or downloadable ZIP.
- Added an optional systemd **user** service installer on Debian (never installs a DNS service or firewall rules).
- No changes to Cloudflare DNS, active DNS engine, web MFA, existing keys, Caddy or NAT. No automatic backend migration on upgrade; no false claim of end-to-end validation.
- Deliberate limitations: no UDP ASSOCIATE, no iodine TUN adapter, no unverified engine autowiring, no automatic remote client switch; dns2tcp unencrypted requires special caution.

### v0.7.0 integration addon — 2026-11-05
- Pinned AliRezaBeigy Linux AMD64 server/client assets with published SHA-256.
- Interactive resource preflight + yes; no independent service or firewall changes.
- Reuse existing exclusive runner, pinned cert, profile and web client builder.
- Add bilingual SlipStream CLI guidance and multi-resolver generation.
- `upgrade.sh --install-missing` skips SlipStream unless explicitly confirmed separately.

## v0.6.1 — 2026-11-04

- Fix DNSTT Linux amd64 client build failing in systemd-run worker with `go: module cache not found: neither GOMODCACHE nor GOPATH is set`.
- Set explicit root-owned Go `GOPATH`, `GOMODCACHE`, `GOCACHE` at `/var/cache/dns-unified/go` for all worker Go builds; no global systemd or login-shell changes.
- Add regression test for building when `HOME`, `GOPATH`, `GOMODCACHE`, and `GOCACHE` are absent.
- Existing DNSTT listener and keys are not modified by upgrading.

## v0.6.0 — 2026-11-04

- Per-engine guided setup/client UI, source-build jobs with progress state and precise capability labels.
- DNSTT client Linux amd64 binary ZIP, SlipStream Rust preinstalled client packaging, all-engine public guide bundles.
- One-time-token Cloudflare zone preview/apply directly in the DNS panel, never persist token.
- Server health read-only diagnostics, CPU/RAM/swap/port53/resolver status.
- Fixed root-only parent directory permission regression for TOTP, safe upgrade preserving running engines and secrets.
- Additional tests for authenticated new endpoints, CSRF, fixed-action job allowlist, zip secret exclusions and web UI.

# Changes

## v0.5.0 — Mandatory TOTP 2FA

- Mandatory RFC 6238 / 30s / 6-digit TOTP with on-server generated QR code, compatible with standard authenticator apps.
- First-login gated enrollment: password alone grants no privileged API access.
- Ten single-use recovery codes, stored as salted hashes; protected regeneration requiring a fresh TOTP.
- TOTP anti-replay across sessions; persistent token generation guards sessions after reset and code rotation.
- Rate limiting, CSRF, secure cookie support, HttpOnly, SameSite, idle and absolute expiry.
- Root-only interactive reset CLI; MFA state stored persistently with 0700/0600 filesystem access.
- New security dashboard; 47 automated tests pass in local environment.
- Added `qrcode` dependency, systemd protected MFA write directory, and Persian setup guide.

# v0.4.1

- Add manual DNS delegation verification for all nine engines using authoritative parent referrals, with two recursive resolvers for zone discovery and A validation; separate from real tunnel health.
- Reject profiles whose hostname does not use their engine-specific DNS label.
- Install bind9-dnsutils for the verification UI; interactive installer offers install-all by default while respecting explicit refusal.
- Report `exclusive_healthy` in service status; preserve off-by-default tunnel services and rollback semantics.

# Changelog

## 0.4.0 — Multi-Core and independent Cloudflare records

- Nine logical engines (MasterDnsVPN, SlipStream Rust, DNSTT, NoizDNS, VayDNS, Soar, iodine, dns2tcp, Xray FinalMask XDNS).
- One A record plus **nine separate NS delegations**, immutable per-engine DNS labels by default.
- Safe Cloudflare preflight, no overwriting unmanaged records, hidden one-shot token; per-engine profile update.
- Method taxonomy, per-core form fields (including VayDNS MTU/record type/compat and Soar allowed ports), DNS and Methods tabs.
- Opt-in installer attempting all nine upstream executable dependencies, with itemized install report and no service starts.
- Key-initialization helper with no overwrite, and a protected Soar direct-proxy acknowledgment.
- Expanded unit selection/health monitoring and tests.
- **Known limitations:** NoizDNS CLI variants may require PT adapter, XDNS needs real native Xray JSON, untested live VPS/client connection, no client-side switching.

## 0.3.0

Initial Cloudflare single delegated-domain automation (now legacy `--single`).

- Add Persian operational guide `docs/OPERATIONS_FA.md`.

### v0.4.2 — Optional HTTPS administration
- Added independent `panel.DOMAIN` Cloudflare A-record CLI, conflict-safe and never touching nine tunnel DNS delegations.
- Added optional Caddy/Let's Encrypt setup with automatic renewal, local reverse proxy, Secure cookies, client-aware rate-limit metadata, HTTP/3 disabled (UDP 443 free).
- Added explicit backup and refusal to replace pre-existing unrelated reverse-proxy configuration.
- HTTPS deployment is optional; no public DNS or firewall changes happen without an interactive approval.

## v0.7.0 — 2026-11-05

- Centralized resumable engine installer (`duc.provision`) with one manifest and atomic per-engine JSON report.
- `bash upgrade.sh --install-missing` resumes missing server binaries and configuration, skips installed/active engines, and keeps DNSTT running.
- Eliminate duplicate all-engines shell implementation; route installer and per-engine web jobs through the same installation strategies.
- Upstream MasterDnsVPN TOML template and shared secret prepared once, existing settings never overwritten.
- Go auto toolchain compatible with MasterDnsVPN Go 1.25 source, explicit Go module caches, one-process compile.
- Optional SlipStream Rust build only with `--include-heavy` and sufficient machine resources; NoizDNS/XDNS reported as needing audited adapters instead of false readiness.
- MasterDnsVPN and VayDNS Linux AMD64 client builds from matching upstream source; Master client ZIP contains a confidential shared key and is restricted to authenticated download.
- Exclusive Mode refuses a switch while bulk provisioning holds the lock. Report surfaced inside the setup page.
- No automatic changes to Caddy, Cloudflare, system resolver, firewall, private DNSTT key or active UDP/53 listener.

### v0.7.0 — SlipStream client options & usage guide refresh (2026-11-05)
- Integrated bilingual **Client Options / Using the Tunnel** explanations into the web Settings, Methods, Workflow panels and downloadable guide/client ZIPs.
- Corrected recursive `--resolver` versus direct `--authoritative` guidance; documented all requested client CLI options and the experimental, disabled `--gso` flag.
- Updated SSH mode verification to a client-first **real SSH handshake**, because the pinned release may time out when the remote side sends the first bytes (e.g. `ssh-keyscan`).
- Clarified that client port is a **raw TCP forward**, not auto-SOCKS; added conditional instructions for authenticated SSH `-D`, a separately provisioned SOCKS5 backend, and a separately provisioned TCP-only Shadowsocks backend. Corrected the `ss-local` example to target the SlipStream local forwarded TCP port.
- Documentation-only changes. No Dante/Shadowsocks installation, NAT/firewall rules, new service units, UDP/53 switching, credential distribution, or daemon startup.


- v0.7.0 Dante backend: authenticated localhost SOCKS5, web install/job/status/switch, rollback to SSH, no DNS-53/NAT interference.
