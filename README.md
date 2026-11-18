# DNS Unified Control

**One control plane for DNS-based tunneling engines, with safe deployment, a shared authenticated backend, and explicit lifecycle checks.**

[راهنمای فارسی](README_FA.md) · [Architecture](docs/ARCHITECTURE.md) · [Multi-Engine P1](docs/MULTI_ENGINE_P1_FA.md) · [Changelog](CHANGELOG-v0.10.6.md) · [Security](SECURITY.md)

> **Current release: v0.10.6 — Multi-Engine P1 (experimental integration).** The software is not yet verified for seven-engine production operation. In particular, CottenDNS provisioning and real-client interoperability are still pending. Installing/upgrading the software **does not** activate a DNS tunnel, change Cloudflare records, or disrupt a running engine on purpose.

## The goal

Managing DNS-tunnel implementations separately can mean juggling different binaries, keys, systemd services, client packages, DNS delegations, and health checks. **DNS Unified Control (DUC)** aims to provide one consistent administrative interface for those tasks, while keeping each engine's transport, secrets, and limitations explicit.

Its design goals are:

- **One product, multiple engines:** a single Web UI, local TUI, and privileged Agent sharing the same configuration and engine registry.
- **Safe operations:** read-only preflight, explicit `yes/no` confirmation, health gates, tracked checkpoints, and best-effort recovery; never claim a failed setup is ready.
- **Two operating modes:** **Exclusive** (one selected engine, default) and **Multi-Engine** (a domain-aware DNS router forwarding to independent loopback engine listeners).
- **Consistent egress:** the shared **authenticated Dante SOCKS5** service stays on `127.0.0.1:1080` for compatible transports; protocol-specific exceptions must be handled transparently.
- **Portable installation:** no hard-coded domain or public VPS address; local instance identity and configuration are created per server.
- **Visibility and honest readiness:** service status, preflight issues, and separate TUI vs public Web/TLS completion.

## Architecture at a glance

```text
Client application (FoxyProxy, v2rayN, etc.)
         |
Native selected engine client (typically 127.0.0.1:2080)
         |
DNS resolver / delegated DNS zone
         |
VPS public UDP/53 (+ TCP/53 where supported)
         |
    +----+---------------------------------------------+
    | Exclusive Mode (default)                          |
    | One selected DNS engine                            |
    +---------------------------------------------------+
    | Multi Mode (P1, opt-in)                            |
    | DUC DNS Router -> engine-specific loopback ports    |
    +----+----------------------------------------------+
         |
Engine-specific forwarding / adapter
         |
Shared authenticated Dante 127.0.0.1:1080 (when compatible)
         |
VPS outbound network
```

The Multi router forwards DNS messages by **delegated zone** (not by combining engine protocols or aggregating a client's bandwidth). It does not become an open recursive resolver. For cloud NAT setups, the router binds to the server's actual interface address, not an assumed public address.

## Project capabilities

| Area | Current capabilities / state |
| --- | --- |
| Web and TUI | Local administrative UI, guarded API, shared privileged Agent, engine status and controls |
| Lifecycle | One `install.sh` entrypoint; Fresh / Resume / Upgrade / Repair detection; read-only plan; checkpoints and local health validation |
| Authentication | Panel password and MFA support; restricted Agent socket; dedicated system service account |
| Network backend | Dante SOCKS5 on VPS loopback with authentication and status checks |
| Exclusive mode | Existing supported DNS engines can be selected individually |
| Multi-Engine P1 | DNS router with UDP/TCP forwarding, zone routing, loopback adapters, Web/TUI controls and preflight; **not field-certified** |
| Public Web completion | Certificate validity, renewal, HTTPS routing and DNS are individually checked; missing public TLS means Web remains incomplete |
| Cloudflare | Opt-in token checks, guarded DNS-01 certificate setup and separately confirmed record updates |
| Monitoring | Health/readiness APIs and engine/host diagnostics; availability and measurement coverage vary by engine |

### Engines

The project's wider engine registry covers **MasterDnsVPN, Soar, SlipStream Rust, DNSTT, NoizDNS, VayDNS, iodine, dns2tcp, and XDNS**. Engine support and operational maturity vary; some adapters require manual configuration or lack field validation.

**The requested seven-engine Multi configuration** is:

```json
{
  "mode": "multi",
  "engines": ["MasterDnsVPN", "Soar", "CottenDNS", "SlipStream", "NoizDNS", "DNSTT", "VayDNS"]
}
```

In v0.10.6, **CottenDNS is a reserved adapter slot, not a bundled, tested server deployment**. Some other engines also need binaries, keys, compatible DNS behavior and client field tests. Preflight must block activation where requirements are absent. The broader engine list does **not** imply every engine can forward SOCKS5 identically.

## Installation and upgrades

**Target:** supported Ubuntu/Debian Linux VPS with Python 3, systemd and root access. A working DNS delegation, provider firewall settings and a public IPv4 may be required for live DNS traffic. Cloud NAT hosts can have a *private* local interface IP.

Download the source ZIP for the tagged version, extract it, then run:

```bash
cd dns-unified-control
python3 scripts/verify-release.py
sudo bash install.sh --dry-run   # no changes; detects operation
sudo bash install.sh             # interactive approval, default no
```

The installer checks the existing instance and chooses Fresh / Resume / Upgrade / Repair. Keep out-of-band access and backups when working on a live VPS. `release-manifest.json` provides file-integrity checks, **not** an authenticity signature or an automatic end-to-end security guarantee.

### Read-only Multi readiness

```bash
sudo /opt/dns-unified-control/.venv/bin/python -m ducmulti.cli status
sudo /opt/dns-unified-control/.venv/bin/python -m ducmulti.cli plan \
  --mode multi \
  --engines master,soar,cotten,slipstream,noizdns,dnstt,vaydns
```

The `plan` command is read-only. **Do not apply Multi Mode to a production VPS until every selected engine passes preflight and a controlled end-to-end client test.** Mode changes require explicit approval, and rollback covers controlled failures only (not sudden power loss).

### Public HTTPS and DNS

TUI/local readiness and public Web readiness are separate. A valid HTTPS certificate by itself is insufficient: routing on port 443, certificate renewal and the panel's A record must also be verified. Port ownership by existing software (e.g., Xray/HAProxy) must be handled without destroying those services. Public panel DNS changes and DNS tunnel NS changes are distinct, guarded operations. **Do not switch NS delegation before verifying a real client against the new server.**

## Security and operational scope

- Never commit credentials, private keys, Cloudflare tokens, TOTP seeds or server backups. Runtime data belongs under restricted system directories, not in Git.
- Avoid exposing the Dante port or the local Web port publicly; use a verified HTTPS reverse-proxy route or SSH port forwarding as appropriate.
- Client packages may contain secrets; generate and transfer them securely.
- Review upstream projects and their separate license obligations before redistribution or bundling.
- This repository is a development/integration release; results from automated tests are not equivalent to live DNS resolver or transport compatibility tests.

## Roadmap

1. Real-world interoperability testing of the seven-engine mode, with safe activation and recovery.
2. CottenDNS adapter provisioning, resolver selection, packet-loss tuning, Survival profiles and field measurements.
3. Stable public HTTPS onboarding across existing reverse proxies and automatic renewal verification.
4. User accounts, usage limits, connection reporting and deeper diagnostics, implemented inside DUC (no separate Soar-Server admin panel).
5. Reproducible builds, release automation, CI and versioned dependency pinning.

## Documentation and status

- [v0.10.6 change notes](CHANGELOG-v0.10.6.md)
- [Multi-Engine technical details (Persian)](docs/MULTI_ENGINE_P1_FA.md)
- [Lifecycle guide (Persian)](docs/LIFECYCLE_V0103_FA.md)
- [Public Web completion guide (Persian)](docs/WEB_HTTPS_BOOTSTRAP_V0102_FA.md)
- [Historical README](docs/README_HISTORY_PRE_V0106.md)
- [Security policy](SECURITY.md)

## Licensing

**A project-wide redistribution license has not yet been selected.** Public visibility alone does not grant unrestricted reuse rights. Third-party dependencies and engines retain their own licenses; please verify compatibility before packaging or distributing them. Contributions and external deployments should await a clear project-wide license decision.
