# DNS Unified Control v0.9.0 — Native Clients + Shared Dante

No client Gateway. Read `docs/V090_NATIVE_SOCKS_FA.md` before changing active engines.

# DNS Unified Control v0.8.1 — Shared Dante + One-Port SOCKS5 Gateway

**Upgrading v0.7.0:** This is a complete source ZIP including all prior Dante/SlipStream integration; extract over `/root/dns-unified-control` then run `bash upgrade.sh` as root. The upgrade preserves `/etc/dns-unified`, active DNS service, keys, TOTP, HTTPS and admin password, and restarts only Web/Agent services. No backend migration is automatic.

### Target architecture

- **VPS:** one authenticated local `dns-unified-dante.service` on `127.0.0.1:1080` (independent of Exclusive Mode). One DNS engine on UDP/53, never a second independent tunnel daemon or NAT redirect.
- **Audited raw-TCP engines:** SlipStream, DNSTT, VayDNS can explicitly point to the SAME Dante backend via the `Unified SOCKS Gateway` panel section. NoizDNS is experimental/unverified; dns2tcp is **unencrypted** and should not be coupled to credential-bearing SOCKS without additional protection. Original targets are preserved for rollback on new changes.
- **Native SOCKS:** MasterDnsVPN uses its own client SOCKS5 listener (`127.0.0.1:18000`) and is *not* chained through Dante.
- **Linux client:** downloadable standard-library-only `duc_socks_gateway.py` presents **SOCKS5 TCP** to apps on `127.0.0.1:2080`, independently of the active tunnel. It authenticates upstream to Dante where needed. Tunnel clients use internal local ports (SlipStream 22080, DNSTT 22081, VayDNS 22082, dns2tcp 22083, NoizDNS 22084). Choose the active engine with `select ENGINE` without changing v2rayN port.
- **Not automated yet:** The client must start the corresponding DNS tunnel program and locally select that engine whenever VPS switches; no auto-detection or remote client process control. iodine needs TUN-to-SOCKS adaptation and other unverified engines remain manual. The Gateway supports TCP CONNECT only (no UDP ASSOCIATE).
- **Credentials:** web download is secret-free. A root-only CLI on the VPS exports a separate private `gateway-config.json` (mode 0600), which must be copied securely to the client. The local Gateway is strictly bound to loopback, with no local auth; Dante still requires credentials.

### Deployment

```bash
cd /root
unzip -tq DNS-Unified-Control-v0.8.0-Unified-SOCKS.zip
unzip -oq DNS-Unified-Control-v0.8.0-Unified-SOCKS.zip
cd /root/dns-unified-control
bash upgrade.sh
```

In the panel choose **راه‌اندازی و کلاینت‌ها → Unified SOCKS Gateway**. Install/verify the one Dante backend if needed; select only known encrypted TCP engines, then explicitly attach them. If SlipStream is currently running, changing its target requires its brief restart. The upgrade itself never restarts the DNS engine.

On VPS, when ready, generate client private configuration (DO NOT paste credentials into chat):

```bash
PYTHONPATH=/opt/dns-unified-control /opt/dns-unified-control/.venv/bin/python -m duc.unified status
PYTHONPATH=/opt/dns-unified-control /opt/dns-unified-control/.venv/bin/python -m duc.unified export-client /root/duc-gateway.json
```

Download the secret-free Linux Gateway ZIP from the web UI. Securely copy `/root/duc-gateway.json` as `gateway-config.json` beside `duc_socks_gateway.py` on Debian, set permissions `chmod 600 gateway-config.json`, and follow `README_FA_EN.md` in the Gateway ZIP. Do not run old SlipStream on port 2080 at the same time as the Gateway: launch it internally on **22080** instead.

---

# DNS Unified Control v0.6.0 — Guided Operations + Client Packages

**Release 0.6.0 (2026-11-04).** See [`docs/V060_OPERATIONS_FA.md`](docs/V060_OPERATIONS_FA.md) for the full Persian operating and upgrade guide.

## Upgrade an already running v0.5.0 VPS

Transfer `DNS-Unified-Control-v0.6.0.zip` to `/root/` on the VPS, then:

```bash
cd /root
unzip -oq DNS-Unified-Control-v0.6.0.zip
cd /root/dns-unified-control
sudo bash upgrade.sh
systemctl is-active dns-unified-web.service dns-unified-agent.socket dns-unified@dnstt.service caddy
```

The upgrader preserves existing `/etc/dns-unified` profiles, keys, dashboard password, TOTP, Caddy and Cloudflare records; it does **not** restart an active tunnel engine. Web/Agent are restarted to load the new version. Back up the VPS first.

### v0.6 features

- Per-engine **Setup & Client** tab for all nine engines (resolver and port selection, safe commands, verified/unsupported labels, downloadable public guide/profile ZIP, server diagnostics).
- DNSTT Linux amd64 client source build + authenticated ZIP download (binary, README, public key); SlipStream Rust Linux amd64 package if a trusted client executable is installed (public TLS certificate only).
- Single-engine source/package installation via audited fixed-action transient systemd jobs where supported; never automatically starts engines; no arbitrary shell execution.
- Cloudflare DNS 10-record dry-run/apply from the panel, token one-time and not stored, with `Zone Read` / `DNS Edit` requirements, conflict checks and profile updates.
- Permanent fix for `/var/lib/dns-unified` MFA directory permissions discovered during live installation.
- Clear separation of recursive DNS delegation check, systemd active status and true end-to-end client connectivity.

**Limits:** Nine protocol families are listed, but executable client building is verified/implemented only for DNSTT and packaging for an already installed SlipStream Rust client. Other engines receive version-aware guides, not fictitious compatible binaries. Source builds need review, CPU, RAM and network. Public panel hardening and rotation of exposed credentials are still the operator's responsibility.

---

# DNS Unified Control v0.5.0 — TOTP Secure Web Panel

**Update 2026-11-04:** Mandatory time-based two-factor authentication (TOTP) is integrated into the web dashboard. No server engine management API is accessible after password login alone. On first login, the panel requires TOTP enrollment with an on-server QR code, then issues ten one-time recovery codes. Subsequent logins require a 6-digit 30-second authenticator code or an unused recovery code. Includes per-IP/account attempt throttling, replay protection, CSRF, session ID rotation, recovery code regeneration, and local root-only emergency reset. See [Persian TOTP guide](docs/TOTP_AUTH_FA.md).

**Important upgrading note:** Persistent TOTP configuration is in `/var/lib/dns-unified/mfa/` (not inside the source ZIP). The installer preserves it on subsequent upgrades. Run first-time enrollment over an SSH port forward before exposing the panel to the public internet. Cloudflare DNS records, tunnels, and Exclusive Mode are unchanged in this release.

# Previous multi-core functionality (v0.4.x)

**Purpose:** Admin web panel on one Debian/Ubuntu Linux VPS, one public IPv4, **nine distinct authoritative DNS subdomains**, and **only one DNS tunnel engine active at once**. All installed binaries remain on disk when inactive. Switching preserves DNS delegations. The client is configured **separately**.

## Scope and safety

This repository is a functional **server-side management MVP**, **not a verified end-to-end VPN**. It can validate permitted settings, inspect installed binaries, start/stop the corresponding systemd units, and attempt rollback. Real client ↔ resolver ↔ VPS connectivity is **not** validated by systemd. Some upstream engines need manual configuration/compatibility work detailed below. Cloudflare writes require the user's explicit confirmation, and no API token is stored in the project or the panel.

- Web app: FastAPI at `127.0.0.1:8088`, password + mandatory TOTP/recovery codes + CSRF; use an SSH port forward for first enrollment.
- Privileged agent: root `systemd` socket-activated service, Unix socket restricted to web group.
- `dns-unified@ENGINE.service`: *exclusive* execution, no service auto-enabled at boot.
- Logs: journal tail; VPS CPU/RAM/disk/network monitoring. These **are not tunnel throughput or DNS loss**.
- Engine args: strictly typed allowlist; no arbitrary command execution from web.
- Install-all: **opt-in**, downloads/compiles third-party source and installs binaries; will produce an itemized failure report instead of silently claiming all installed.
- Be aware: source build versions are not pinned yet; audit GitHub sources/commits before production deployment.

## Engines, families and DNS labels

Choose a real domain whose active authoritative nameservers are managed by Cloudflare. `example.com` below is an **example, not a domain supplied by the user**.

| Engine ID | Family | NS delegated name | Notes |
|---|---|---|---|
| `master` | ARQ, multiple resolvers | `m.example.com` | Upstream MasterDnsVPN, TOML config & shared secret required |
| `slipstream` | Rust QUIC DNS | `r.example.com` | **Mygod/slipstream-rust**, archived upstream, build + TLS setup |
| `dnstt` | Noise/KCP | `d.example.com` | Private/public key pair, forwards to localhost TCP target |
| `noizdns` | Modified DNSTT | `n.example.com` | Binary differs by fork; **requires compatible `-udp` implementation or PT adapter** |
| `vaydns` | KCP/smux | `v.example.com` | MTU, record type, queue, `dnstt_compat`; client DoH/DoT/UDP |
| `soar` | multipath DNS | `s.example.com` | Upstream **pre-release**; direct server is an unauthenticated proxy: extra opt-in required |
| `iodine` | IP over DNS | `i.example.com` | TUN/IP style, not encrypted; server NAT / routing not automated |
| `dns2tcp` | TCP-over-DNS | `c.example.com` | SSH resource; not independently encrypted |
| `xdns` | Xray FinalMask | `x.example.com` | **Xray feature, not separate binary**; explicit audited native Xray JSON required |

**One shared record:** `ns.example.com A YOUR_PUBLIC_IPV4`, `proxied=false` (Cloudflare DNS Only).

**Nine independent records:** each hostname in the table gets its *own* `NS` pointing to `ns.example.com`, not to an IP. No data route is shared merely because all records point to the same IP. All can coexist in DNS; only one service will listen on UDP port 53.

## Supported method / record *classification*

- `TXT`, `A`, `AAAA`, `CNAME`: DNS record types. In this MVP the VayDNS `record_type` argument is generated. XDNS profile record-type/MTU values are **informational templates until the native Xray server.json is authored**.
- `DoH`, `DoT`: **client-to-recursive-resolver** modes supported by VayDNS. They are not server-side switches and do not create Cloudflare HTTPS records.
- `DoQ`: currently **not implemented**; do not mistake it for VayDNS support.
- SOAR refers to **Lantern Soar**, not a DNS `SOA` record or `SOAR` security automation.

## Install on a new VPS (Debian/Ubuntu)

Review shell scripts and upstream source before running as root. Assumes root or sudo, systemd, and access to GitHub/APT. Don't run this installer on a critical host without backup.

```bash
unzip dns-unified-control-v0.4.1-multicore.zip
cd dns-unified-control
sudo bash install.sh
```

The installer:

1. Installs the web app, Unix-socket agent, systemd templates, and asks for a strong admin password.
2. Optionally asks for Cloudflare domain, public VPS IP (can auto-detect), and a **zone-scoped token**. It preflights and provisions **1 A + 9 NS records**, and updates each profile to its own domain.
3. Interactively offers to install **all upstream engine binaries** (default Yes; explicit install script review recommended). For automation, set `DUC_INSTALL_ENGINES=1`; otherwise noninteractive installs only the control panel. Third-party installation failures are itemized and do **not** start the engines.

To opt into group binary installation noninteractively from the extracted directory:

```bash
sudo bash scripts/install-all-engines.sh
sudo bash scripts/prepare-engine-secrets.sh
cat /var/lib/dns-unified/install-results.json
```

**Do not expose the panel publicly over HTTP.** Use an SSH port forward from your own computer:

```bash
ssh -N -L 8088:127.0.0.1:8088 root@YOUR_VPS_IP
# In your local browser: http://127.0.0.1:8088
```

## Cloudflare automatic per-engine record provisioning

**Prerequisites:** add the zone to Cloudflare, delegate its parent domain at the registrar to Cloudflare's assigned nameservers, and wait until Cloudflare reports the zone `active`. Cloudflare cannot change the registrar's nameservers using just a Cloudflare DNS token.

Give the token **Zone → Zone → Read** and **Zone → DNS → Edit** on *this zone only*. No Global API Key. CLI prompts for token using hidden input; **do not put it in command arguments or web forms**.

```bash
sudo env PYTHONPATH=/opt/dns-unified-control \
  /opt/dns-unified-control/.venv/bin/python -m duc.cloudflare_dns \
  --domain YOUR_DOMAIN --ip YOUR_PUBLIC_IPV4 --dry-run
# Omit --dry-run only when you want to apply changes:
sudo env PYTHONPATH=/opt/dns-unified-control \
  /opt/dns-unified-control/.venv/bin/python -m duc.cloudflare_dns \
  --domain YOUR_DOMAIN --ip YOUR_PUBLIC_IPV4
```

The CLI now defaults to **all nine independent NS records**. It refuses conflicting unmanaged records (never deletes records). The `--single --tunnel-label v` flag exists only for migration from v0.3's single-subdomain layout. It is **not** recommended with v0.4. DNS API operations are not atomic; if a later write fails, check the Cloudflare dashboard and rerun safely. Public DNS propagation takes time. Per-engine domains must retain their dedicated prefix (`m`, `r`, `d`, `n`, `v`, `s`, `i`, `c`, `x`); the panel rejects attempts to assign a different engine's prefix.

The Web panel's **DNS** tab displays per-engine planned domains and a manual **Verify 9 delegations** button. It discovers authoritative nameservers for the parent zone via `1.1.1.1` and `8.8.8.8`, queries parent-zone delegations directly (no recursion), and checks a public IPv4 A record. This avoids false negatives when an inactive child tunnel service cannot answer DNS. This checks recursive DNS visibility only, NOT the real client-to-server tunnel, and does not independently prove the A record points to your intended VPS unless you check the displayed IP. The panel **does not accept or save Cloudflare tokens**.

## Preparing engine configuration

`sudo bash scripts/prepare-engine-secrets.sh` will initialize DNSTT/VayDNS/NoizDNS keys **if each binary supports `-gen-key`**, Soar key files, and passwords for iodine/dns2tcp. It never overwrites existing keys. Some engines need extra steps:

- **MasterDnsVPN:** use upstream `server_config.toml.simple` as `/etc/dns-unified/engines/master/base.toml` and upstream-compatible `/etc/dns-unified/keys/master.key`; the manager renders a derived TOML when starting. Do not guess the secret format.
- **SlipStream Rust:** generate certificate, key and reset seed with `sudo bash scripts/prepare-slipstream-rust.sh`; inspect that script first. The Rust client must pin the server certificate. Older upstream is archived and builds may fail on newer toolchains.
- **NoizDNS:** release assets from `SamNet-dev/dnstm-setup` are optional and not equivalent to a universal CLI. Some NoizDNS distributions operate only via a pluggable transport; if the binary lacks `-udp`, the panel will **refuse to start it** until a compatible, audited wrapper is supplied. `dnstt-server` should not be overwritten by the Noiz fork.
- **VayDNS:** requires matching `-dnstt-compat` setting on client and server if compatibility is enabled; record type and MTU must agree with client. VayDNS DoH and DoT are *client-side resolver transport choices*.
- **Soar:** public-key access is *not* per-user authentication. The direct server defaults to limited public destination ports `80,443` or `443` only. To allow this experiment only after reviewing its abuse risk: `sudo touch /etc/dns-unified/keys/soar.public-proxy-ack && sudo chmod 600 /etc/dns-unified/keys/soar.public-proxy-ack`. Prefer restricting who can reach the server using firewall/SSH modes if your environment permits.
- **iodine:** creates a TUN interface and needs route/NAT setup; a running process alone does not mean client traffic can reach the internet.
- **dns2tcp:** the manager forwards an `ssh` resource to `127.0.0.1:22`; TLS/SSH must handle confidentiality.
- **XDNS:** install official Xray, then supply **audited native Xray config** to `/etc/dns-unified/engines/xdns/server.json` for mKCP + FinalMask xdns and the chosen delegated subdomain. The manager will run `xray run -test -c ...` before allowing a switch. Do not treat the panel's `xdns_record_type`/`xdns_mtu` fields as configuring the native JSON by themselves.

## Service switching and monitoring

All nine systemd services use one template: `dns-unified@ENGINE.service`. **Never independently enable them on boot**; use the panel, which stops prior managed service, checks port ownership, starts the target, checks process health, and attempts rollback on failure. Active connections **will be interrupted** and the client must switch separately. Always maintain independent SSH/VPS console access. This manager intentionally does not disable `systemd-resolved`, replace `/etc/resolv.conf`, change UFW, or change the user's UDP firewall policy.

```bash
sudo bash diagnose.sh
sudo systemctl is-active dns-unified@vaydns.service
sudo journalctl -u dns-unified@vaydns.service -n 50 --no-pager
sudo ss -lntup | grep ':53' || true
# External delegation checks (install bind9-dnsutils if necessary):
dig +short NS v.YOUR_DOMAIN @1.1.1.1
dig +short A ns.YOUR_DOMAIN @1.1.1.1
```

Panel monitor: VPS CPU/RAM/disk/network, unit status/CPU/RSS and logs. The DNS verification is a *separate manual* button and never continuously probes external resolvers. **True packet loss, client latency, per-resolver health, tunnel speed, actual public reachability, credential handoff and cross-machine automatic synchronized switching are still future integration tasks.**

## Compatibility / upgrade notes

From v0.3: shared `v.DOMAIN` is not automatically inferred/migrated from existing profiles because old usage may be deliberate. Run the new Cloudflare provisioner and approve changes; it updates each engine profile to its dedicated hostname. Never delete the old shared NS record until you know clients no longer use it.

Upstream references and license notices: [`docs/UPSTREAM.md`](docs/UPSTREAM.md). Changes: [`CHANGELOG.md`](CHANGELOG.md). Security model: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Optional public HTTPS dashboard (v0.4.2)

**Separate subdomain:** `panel.YOUR_DOMAIN` is a Cloudflare **A** record (DNS-only on initial setup), not one of the nine tunnel **NS** delegations. There is no interaction with UDP 53. The installer can optionally run `sudo bash scripts/setup-panel-https.sh`, which provisions the panel A record with a temporary, hidden Cloudflare token and configures a Caddy reverse proxy to `127.0.0.1:8088` with automatic HTTPS and automatic certificate renewal. It disables Caddy HTTP/3 to keep UDP 443 free, but **TCP 80 and 443 must be available and publicly reachable** for normal ACME validation. The script never edits your existing UDP firewall rules.

Do not mistake script exit for proof of a valid certificate; check `journalctl -u caddy` and `curl -I https://panel.YOUR_DOMAIN`. The app remains password-protected, and the browser uses Secure session cookies under HTTPS. The public panel is a sensitive administrative surface: use a firewall allowlist or Cloudflare Zero Trust Access before exposing it broadly. Details, prerequisites and safe fallback: [`docs/PANEL_HTTPS.md`](docs/PANEL_HTTPS.md).

## Unified resumable provisioning (v0.7.0)

Use `bash upgrade.sh --install-missing` to upgrade the web panel and resume installing any missing server engines without restarting a currently running tunnel. `duc.provision` is the single installation orchestrator used by both this command and individual web jobs; `/var/lib/dns-unified/provision-report.json` records per-engine results atomically. It deliberately does not activate new engines, change DNS stub settings, or change Cloudflare records. On low-memory machines, SlipStream Rust is deferred unless `--include-heavy` is supplied and resource checks pass. NoizDNS and XDNS remain explicitly review-required until compatible adapters/configs are supplied. Read `docs/V070_PROVISION_FA.md` for Persian instructions and limitations.


### SlipStream AliRezaBeigy pinned release (consent required)
See `docs/SLIPSTREAM_ALIREZABEIGY_FA.md`. After `bash upgrade.sh` run `bash /opt/dns-unified-control/scripts/install-slipstream-ali.sh`. The upstream deployment script is never executed. Exclusive Mode owns UDP/53.

### SlipStream imported release — web and CLI (v0.7.0 integration fix)

Choose **SlipStream** in **Workflow / راه‌اندازی و کلاینت‌ها**. A read-only hardware preflight shows RAM, swap, CPU, disk, running engine and verified imported binaries. The authenticated admin can explicitly confirm a fixed `install-server:slipstream` job. The job installs/verifies pinned AliRezaBeigy server+client and TLS assets, **without** starting a service, changing DNS port 53, Caddy, firewall, or existing keys. Build/download the Linux client package separately. All mutation endpoints require a full MFA-backed session and CSRF.

From root CLI, `bash /opt/dns-unified-control/scripts/install-slipstream-ali.sh` runs an explicit installer without a second `yes` prompt. Use `python -m duc.slipstream_ali --preflight` for a read-only machine-readable assessment. Do not start the upstream standalone deploy script. Existing pinned binaries are verified and preserved rather than overwritten.

## SlipStream Client Options / Using the Tunnel (FA + EN)

See [`docs/SLIPSTREAM_CLIENT_OPTIONS_FA_EN.md`](docs/SLIPSTREAM_CLIENT_OPTIONS_FA_EN.md).
The latest documentation is displayed under **Settings → SlipStream**, **Methods**, and **Workflow / Client** and is included in exported SlipStream Linux client ZIPs. The imported Rust client forwards **raw TCP** to the configured loopback target. The current target is SSH `127.0.0.1:22`; SOCKS5 and Shadowsocks modes require **separately provisioned, authenticated localhost backends** and an explicit target update and engine restart. This update does not create proxy daemons, firewall changes, or independent services, and it does not switch Exclusive Mode.


## v0.7 Dante backend (SlipStream)

Dante is a **localhost-only authenticated TCP SOCKS5 backend**, not an independent DNS engine.
The privileged job `install-dante/slipstream` installs Ubuntu's `dante-server`, creates the
DUC-managed `dns-unified-dante.service` and `/etc/dns-unified/danted.conf`, and generates
root-only credentials at `/etc/dns-unified/keys/dante-auth.json`. It does **not** stop a running
DNS engine, take UDP/53, change NAT, or run the upstream deploy script.

Use the **Dante SOCKS5 Backend** card in web *Workflow & Clients*: install then activate.
When active, the SlipStream target becomes `127.0.0.1:1080` and the SlipStream service
is restarted with the normal Exclusive Mode mechanism. The current SSH backend can be
restored from the same card. Credentials are **never returned by the web API**. On VPS:

```bash
PYTHONPATH=/opt/dns-unified-control /opt/dns-unified-control/.venv/bin/python -m duc.dante status
PYTHONPATH=/opt/dns-unified-control /opt/dns-unified-control/.venv/bin/python -m duc.dante credentials
```

The second command returns a private v2rayN SOCKS URI (localhost port 2080); don't
post it publicly. The client still runs `slipstream-rust-client` and the SOCKS protocol
is handled by Dante on the server. Only TCP CONNECT is supported via this bridge.

## v0.8.1 — Authenticated one-link client setup

The Linux gateway now requires SOCKS5 username/password on `127.0.0.1:2080`. On the VPS (root), export a private setup shell script: `PYTHONPATH=/opt/dns-unified-control /opt/dns-unified-control/.venv/bin/python -m duc.unified export-setup /root/duc-gateway-setup.sh`. Transfer privately using scp and run `sh ./duc-gateway-setup.sh` on Linux alongside the publicly downloadable Gateway. This creates the private config without manually editing JSON and prints a credentialed v2rayN SOCKS URI. Delete the setup script on both ends after running. On Debian run `python3 duc_socks_gateway.py serve`; run the matching tunnel client at its local internal port separately. This design **does not embed passwords in public downloads or expose them to the panel API**.
