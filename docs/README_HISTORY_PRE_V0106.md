> **v0.10.6 Multi-Engine P1:** [changelog](CHANGELOG-v0.10.6.md) · [فارسی](docs/MULTI_ENGINE_P1_FA.md). Mode remains Exclusive by default; review readiness before any Multi switch.

# DNS Unified Control v0.10.3 — Lifecycle Manager

**Use one entrypoint on new or existing Debian/Ubuntu VPS:** `sudo bash install.sh`. It verifies the release manifest, detects Fresh / Resume / Upgrade / Repair, asks for explicit approval, saves root-only checkpoints and verifies Web/Agent/Dante before declaring local readiness. See [راهنمای Lifecycle](docs/LIFECYCLE_V0103_FA.md).

Existing installations preserve instance identity, server keys, MFA, Dante credentials and Cloudflare DNS. Public HTTPS remains a separately verified step; no DNS or engine cutover is automatic.

Read-only options: `sudo bash install.sh --dry-run` and `sudo bash install.sh --status`.

---

# DNS Unified Control v0.10.2 — Runtime & TLS Readiness

Fixes unprivileged Uvicorn startup on first install and gates successful installs on real local HTTP readiness. TLS is tracked separately: on a replacement VPS, public certificate issuance through HTTP-01 must follow an approved panel A-record cutover; DNS-01 pre-issuance is not yet automated. See [راهنمای بوت‌استرپ و TLS](docs/WEB_HTTPS_BOOTSTRAP_V0102_FA.md).

---

# DNS Unified Control v0.10.1 — Guided First Install

**On a new VPS, run `sudo bash install.sh` from the extracted project.** It first assesses OS/resources/conflicts and then asks for domain, public IPv4, an optional read-only Cloudflare token check, swap, and additional engines. No DNS records or DNS engine start is performed during installation. For commands and safety read [راهنمای نصب مرحله‌ای](docs/GUIDED_INSTALL_V0101_FA.md). Existing installations use `bash upgrade.sh`; do not run a fresh install on a live VPS.

---

# DNS Unified Control v0.10.0 — Portable Product Foundation

**A fresh installation is a new instance, not a migration of old credentials.**

The software can be installed on separate supported Debian/Ubuntu VPS hosts with a new domain/IP and separate keys. Each installation owns one `instance.json` identity; no Cloudflare records are changed during install. This is an early integration release, not a production-grade package with an atomic rollback guarantee.

Check extracted files first with `python3 scripts/verify-release.py` (checksums detect corruption, **not** publisher authenticity). Then run `bash scripts/fresh-install.sh --audit --domain YOUR_DOMAIN --ip YOUR_PUBLIC_IPV4` then `sudo bash scripts/fresh-install.sh --install --domain YOUR_DOMAIN --ip YOUR_PUBLIC_IPV4` on a new host. The installer asks for explicit confirmation and does not start a DNS engine. `--with-engines` can opt into available additional engines. Existing installations use `bash upgrade.sh` and retain previous identity and credentials.

Read [docs/PRODUCT_INSTALL_FA.md](docs/PRODUCT_INSTALL_FA.md) for support matrix, prerequisites, security, cloud cutover and recovery rules. See historical docs below.

---

# Fresh install on a new VPS (v0.9.9)

Use `bash scripts/fresh-install.sh --audit --domain m2m.diy --ip NEW_FR_IP`, then `sudo bash scripts/fresh-install.sh --install --domain m2m.diy --ip NEW_FR_IP`. **This creates new keys and Dante credentials and never modifies Cloudflare or starts a DNS engine automatically.** Full Persian instructions: [docs/FRESH_FRANCE_FA.md](docs/FRESH_FRANCE_FA.md).

**New in v0.9.8:** Local TUI (run: `sudo bash /opt/dns-unified-control/scripts/duc-tui.sh`) + read-only readiness API. See [docs/TUI_V098_FA.md](docs/TUI_V098_FA.md).

> **v0.9.7 review:** Build/ZIP resolver and local port are now consistent across the Web, Agent and worker. Rebuild old NoizDNS/alternate ZIPs after updating. See [CHANGELOG v0.9.7](CHANGELOG-v0.9.7.md).

> **v0.9.6:** ساختار پنل بازطراحی شد: کلاینت‌های Native/SlipNet با Job مستقل، صفحهٔ Dante جدا و Registry مشترک برای TUI آینده. جزئیات: [CHANGELOG v0.9.6](CHANGELOG-v0.9.6.md)، [معماری Web/TUI](docs/UI_TUI_ARCHITECTURE_V096_FA.md). تست میدانی DNSTT/VayDNS با SlipNet پس از نصب لازم است.

> **v0.9.5 client build fix:** NoizDNS now uses the `v2.5.3 - CLI` release with the pinned Linux binary SHA-256 (GitHub first, checksum-checked SourceForge mirror fallback). See `CHANGELOG-v0.9.5.md`.

# DNS Unified Control v0.9.9 — Fresh Installer, Local TUI and Readiness

## نسخه 0.9.3 — نصب خودکار سمت سرور NoizDNS با Dante مشترک

نصب/ارتقا: نصب اختصاصی `noizdns-server` از `anonvector/dnstt` و کلیدهای مستقل Noise، حفظ موتور فعال و Dante مشترک. کلاینت بومی SlipNet از Release رسمی با SHA-256 دریافت شده و پروفایل `sayedns`+`Stealth` از پنل تولید می‌شود؛ تست واقعی احراز هویت Dante همچنان ضروری است.

## نسخه 0.9.2 — نصب خودکار سرور Soar در نصب و ارتقا

`bash install.sh` و `bash upgrade.sh` اکنون **همیشه** سرور محدودشده Soar را نصب/اعتبارسنجی می‌کنند و اگر کلید وجود نداشته باشد آن را با مجوز 0600 تولید می‌کنند. کلید عمومی نیز از کلید خصوصی مشتق و بررسی می‌شود. نصب ناکام **کد خروجی غیرصفر** می‌دهد؛ نصب ناقص دیگر موفق اعلام نمی‌شود. موتور فعال DNS، Dante، کلیدهای موجود و UDP/53 تغییر نمی‌کنند. تولید/دانلود کلاینت Linux در وب‌پنل باقی می‌ماند. راهنما: `docs/V092_SOAR_INSTALL_FA.md`.

---

## سوابق نسخه‌های قبلی (0.9.1 و 0.9.0)

### نسخه 0.9.1 — نصب Soar از وب‌پنل (منسوخ در 0.9.2)

از بخش «راه‌اندازی و کلاینت‌ها» موتور Soar را انتخاب کن، نصب و تولید کلید را اجرا کن، بستهٔ کلاینت Linux را بساز، از پنل دانلود کن، سپس از «موتورهای تونل» Soar را در Exclusive Mode فعال کن. دستور اجرای کلاینت مستقیم روی 127.0.0.1:2080 از خود پنل دریافت می‌شود؛ یوزرنیم/پسورد همان Dante مشترک است و هیچ Gateway/JSON کاربری لازم نیست. [راهنمای فارسی](docs/V091_SOAR_PANEL_FA.md).

---

# DNS Unified Control v0.9.0 — Native Clients, One Shared Dante

**Project state:** integration release, **not** an end-to-end certification of all nine engines. For complete Persian operating notes see [docs/V090_NATIVE_SOCKS_FA.md](docs/V090_NATIVE_SOCKS_FA.md) and the [field-test matrix](docs/TEST_MATRIX_V090_FA.md).

## Main architecture

```
v2rayN / FoxyProxy 127.0.0.1:2080 (username+password)
      ⇕ SOCKS5 bytes, unchanged
ONE currently selected client binary listening on 127.0.0.1:2080
      ⇕ DNS tunnel via recursive resolver, per-engine protocol
ONE server DNS engine on UDP/53 (Exclusive Mode)
      ⇕ raw TCP
Dante 127.0.0.1:1080 (RFC 1929 username/password; VPS only)
      ⇕ TCP CONNECT
Internet — server egress IP
```

No client-side Gateway, local JSON, SSH `-D` SOCKS proxy or extra DNS server unit.
Each tunnel must support a raw TCP forward to the Dante backend. Currently
**SlipStream Rust, DNSTT and VayDNS** have audited command templates; switch
which *client binary* owns port `2080` when switching the VPS engine.

**No universal Dante support** for every protocol: Master has native SOCKS,
Soar is a secure public-destination dialer with special policies, iodine is IP/TUN,
dns2tcp lacks encryption, NoizDNS requires variant pinning, XDNS needs matched
Xray configs. For Master the output port is configurable in newly built bundles.

## Upgrade — existing VPS

Inspect existing engine and Dante before changing anything:

```sh
systemctl list-units 'dns-unified@*.service' --type=service --state=running --no-pager
systemctl is-active dns-unified-web dns-unified-agent.socket caddy dns-unified-dante
ss -lunp | grep ':53'
ss -lntp | grep '127.0.0.1:1080'
```

Transfer `DNS-Unified-Control-v0.9.0-Native-SOCKS.zip` to `/root`, then:

```sh
cd /root
unzip -tq DNS-Unified-Control-v0.9.0-Native-SOCKS.zip
unzip -oq DNS-Unified-Control-v0.9.0-Native-SOCKS.zip
cd /root/dns-unified-control
bash upgrade.sh
PYTHONPATH=/opt/dns-unified-control /opt/dns-unified-control/.venv/bin/python -m duc.fieldcheck
```

Upgrade saves a code backup under `/root/duc-panel-backup-*`, preserves keys,
Cloudflare DNS, profile settings, TOTP and current DNS tunnel unit, but restarts
web/agent code. Old local Gateway files are removed from `/opt` only after backup.
**Do not run `--install-missing` yet** on a small VPS unless you intend to build
engines. `upgrade.sh` alone does not switch or restart a running DNS engine.

## Authenticated SOCKS URI / SlipStream

Generate SOCKS URI root-only on VPS (contains a Base64-encoded password):

```sh
PYTHONPATH=/opt/dns-unified-control /opt/dns-unified-control/.venv/bin/python -m duc.unified link
```

On Debian, from your SlipStream binary/certificate directory:

```sh
./slipstream-rust-client -r 1.1.1.1:53 -d r.m2m.diy -l 2080 --cert ./slipstream-rust.crt
```

This single TCP listener forwards actual SOCKS handshake to Dante. Do not run
another program on local port `2080` simultaneously. Configure FoxyProxy or
v2rayN for authenticated SOCKS5 and **remote DNS**; disable UDP relay on this
raw TCP node.

## DNSTT and VayDNS

In Workflow → Shared Dante, select DNSTT and VayDNS and attach (default for
fresh profiles, no silent mutation of existing profiles on upgrade).
Prepare matching client binaries and keys, then **stop SlipStream client**,
switch VPS engine through Exclusive Mode, and start that engine's client bound
to local `2080`. See the exact sample commands in the Persian operations guide.
Running a local Python `duc_socks_probe.py` gives actual SOCKS5+HTTPS results.
No network results are preloaded or simulated inside the dashboard.

## Advanced parameters and field measurements

- `VayDNS`: idle timeout, keepalive, KCP window, queue overflow, log level plus MTU/record type/queue settings — wired into server argv.
- `SlipStream`: configured resolver paths, congestion setting, interval, max connections and idle timeout.
- `Master`: native SOCKS listen port (new client ZIP must be built after changes).
- `iodine`: included 10-case client-side trial benchmark, IP-level ping-loss export.
- `/api/workflow/advanced`: source-scoped option support matrix. Unsupported fields are not claimed to be operational.
- `/api/workflow/telemetry`: browser-authenticated view/import of actual client reports; sample-level RTT/HTTPS throughput/request failure and iodine ICMP loss.
- VPS host RX/TX counters are host-wide; `request_failure_pct` is **not** raw DNS packet loss. No per-tunnel DNS loss or wire throughput is invented.

## Automated tests

On a machine with Python dependencies installed:

```sh
PYTHONPATH=. pytest -q tests
node --check web/app.js
```

Results from local tests verify code behavior, mock SOCKS handshake, profile
changes, state storage and API contracts. **They cannot replace real network
field tests** from Debian to DNS resolvers and the VPS.

## Security / lifecycle

Only one DNS engine is active. Shared Dante is bound to loopback and enforces
system account authentication; never make Dante publicly accessible. The panel
uses password + TOTP, CSRF protection, HTTPS (when configured), a privileged
Unix-socket agent and allowlisted engine configurations. No Cloudflare API token,
Dante password or upstream private key is stored in client probe reports.

Before running all engines, read [Operations](docs/V090_NATIVE_SOCKS_FA.md) and
check safe test requirements for unencrypted dns2tcp and direct-proxy Soar.

Historic version-specific instructions are preserved in
[docs/LEGACY_V081_README.md](docs/LEGACY_V081_README.md); they describe the
**removed** optional local Gateway design and should not be followed for v0.9.0.

## v0.9.6 NoizDNS native SlipNet client — field-test evidence

The NoizDNS server is provisioned automatically by the installer, preserving existing keys and active DNS engine. In **Clients → NoizDNS**, build the primary pinned SHA-256-checked SlipNet v2.5.3 CLI Linux amd64 with a secret-free `sayedns`/Stealth profile, or build an **independent, non-Stealth** standard DNSTT client alternative. These packages have different job states and download paths. The native SlipNet CLI provides its own in-process SOCKS5 listener: **no Python Gateway**, no second Dante.

The generated `run-noizdns.sh` now passes an **explicit recursive resolver** (`--dns 1.1.1.1:53`) to disable the observed automatic direct-DNS fallback; override with `DUC_DNS_RESOLVER=8.8.8.8:53` if needed. Example: `DUC_DNS_RESOLVER=1.1.1.1:53 ./run-noizdns.sh`. Stop any previous listener on `127.0.0.1:2080` first. Older v0.9.5 ZIPs must be rebuilt because their launcher did not explicitly pass `--dns`.

**Real field evidence (2026-11-07):** Debian SlipNet v2.5.3 owned port 2080, sent tunneled TXT DNS queries to `1.1.1.1:53`, and returned HTTPS 200 with the VPS public egress IP. Good SOCKS credentials succeeded; bad/missing credentials were rejected. This does **not** independently prove VPS-side Dante authentication logs or resistance against sophisticated DPI. Credential-injection launcher is optional and not needed for the successful field tests; it is sensitive because base64-encoded credentials may appear in process args. See `docs/NOIZDNS_SLIPNET_NATIVE_FA.md` and `docs/UI_TUI_ARCHITECTURE_V096_FA.md`.

### Organized Web panel and future TUI

Engine state, profile configuration, server bootstrap, client-build selection, domain delegation, monitoring and Shared Dante have separate navigation destinations. `duc/client_catalog.py` owns the shared **engine → compatible client** registry consumed through the authenticated Agent API; the Web UI does not hardcode available variants. The planned TUI can consume the same contracts without duplicating browser logic. **A functioning TUI has not yet been implemented.**

## 0.10.4 Public Onboarding (separate from base installation)

Use `sudo bash install.sh --public-plan` to audit public 80/443 port ownership. External DNS/TLS are not mutated by installing or upgrading the base panel. The optional guarded commands are `--issue-cert-dns01`, `--issue-cert-only`, `--publish-panel`, and `--publish-ns --client-verified`. Each requires explicit `yes` and a live readiness check. Tokens are entered only when needed, and never saved in the lifecycle journal.

On port-conflicted hosts, getting a certificate and configuring a **persistent** SNI/HTTPS route are two distinct requirements. Refer to `docs/PUBLIC_ONBOARDING_V0104_FA.md`. Do not cut over a live panel record until the new panel's authenticated HTTPS routing works; do not cut over `ns` until a new native client package has passed a real end-to-end field test.


## 0.10.5 Web completion is an installation gate

Run `sudo bash install.sh` for fresh installation, resume, upgrade or repair.
A locally healthy TUI and Agent do not imply the public Web installation is complete.
The installer now guides certificate issuance/renewal configuration **inside** the
main lifecycle. It records `TUI_READY_WEB_INCOMPLETE` until a valid certificate,
renewal configuration, trusted TLS route serving DUC on port 443, and the panel
DNS A record all pass inspection. See `docs/WEB_INSTALL_COMPLETION_V0105_FA.md`.
Existing proxy listeners are never stopped or reconfigured automatically.

