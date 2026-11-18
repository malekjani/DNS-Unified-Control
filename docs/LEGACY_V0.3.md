# DNS Unified Control

Self-hosted **web management panel** for *exclusive* operation of one DNS tunnel engine at a time on a single Linux VPS and a single public IPv4. Version 0.3: Cloudflare DNS provisioning, SlipStream Rust adapter plus initial MVP with a privileged Unix-socket agent, an unprivileged authentication-protected web panel, configuration forms, systemd control, port conflict detection, rollback on start failure, live VPS resource metrics, service logs, and an audit log.

**Supported server-side adapters** (you must install the upstream executables):
- MasterDnsVPN (`masterdnsvpn-server`, TOML file)
- **SlipStream Rust** (`slipstream-rust-server`, Mygod/slipstream-rust CLI; archived upstream, optional)
- DNSTT (`dnstt-server`, CLI)
- iodine (`iodined`, CLI)
- dns2tcp (`dns2tcpd`, generated config)

DNS TXT/CNAME are record types, not separate servers. DoH/DoT/DoQ are DNS transports; these are **not implemented** as standalone tunnels in this MVP. None of the above are bundled in this archive. No client-side agent, cross-host synchronized switching, or end-to-end packet loss tests are implemented; switching here controls the **VPS server only**.

## Installation (Debian 12+/Ubuntu 22.04+, root access, systemd)

Inspect `install.sh` and deployment unit files before running them.

```bash
unzip dns-unified-control.zip
cd dns-unified-control
sudo bash install.sh
```

The installer installs Python dependencies via pip (internet required); configures user `dns-unified`; installs root agent as systemd socket-activated service and a non-root web app on `127.0.0.1:8088`; prompts for an admin password of >=16 characters. **It does not download or start tunnel binaries.**

From your Linux computer, open the dashboard safely using SSH:

```bash
ssh -N -L 8088:127.0.0.1:8088 root@YOUR_VPS_IP
# Browse to http://127.0.0.1:8088 on your local machine
```

No inbound public 8088 firewall port is required. To run directly on the public Internet, use a TLS-terminating authenticated reverse proxy, enable `DUC_COOKIE_SECURE=1`, and add IP allowlisting; the bundled configuration is **intentionally private**.

## DNS domain delegation

Example (replace `example.com`, never assume `akr.cfd` is registered):

| Type | Name | Value |
|---|---|---|
| A | ns | YOUR_VPS_PUBLIC_IPV4 |
| NS | v | ns.example.com. |

Use `v.example.com` as the domain in the profile for each engine (or configure separate delegated subdomains). If your DNS provider supports proxying, set the A record to **DNS only**.

Open UDP **53** to the VPS in firewall/security-group after you verify your own DNS server doesn't occupy it. Verify with `sudo ss -lunp | grep ':53'`. `systemd-resolved` sometimes binds stub listeners on port 53; this MVP deliberately refuses to switch if the port is occupied, rather than silently modifying system DNS settings.

## Engine binary installation and secrets

Use the upstream project releases or build from source. Install trusted executables under `/usr/local/bin` or another standard root-controlled PATH directory (owner root, not writable by the web account). Check each version's `--help`; interfaces can change upstream.

### MasterDnsVPN

Build upstream `go build -o masterdnsvpn-server ./cmd/server` or use its official release binary, then install it as `/usr/local/bin/masterdnsvpn-server`.

Copy the upstream **full** `server_config.toml.simple` to `/etc/dns-unified/engines/master/base.toml`. The runner makes a validated derived `server_config.toml` at launch, overriding `DOMAIN`, `UDP_PORT`, `UDP_HOST`, `ARQ_WINDOW_SIZE`, `LOG_LEVEL`, `DATA_ENCRYPTION_METHOD` (2–5, default 2), and `ENCRYPTION_KEY_FILE`, while preserving other upstream template settings. Choose a strong encryption method and apply the same method and key to the client. Example key creation (actual format should follow upstream generator): consult upstream installer; then place the **correct key content** in `/etc/dns-unified/keys/master.key` (mode 600 root-owned). Never publish it in the panel or logs.

### DNSTT

Build/install `/usr/local/bin/dnstt-server`. Generate a keypair following your exact DNSTT fork:

```bash
sudo dnstt-server -gen-key -privkey-file /etc/dns-unified/keys/dnstt.key -pubkey-file /etc/dns-unified/keys/dnstt.pub
sudo chmod 600 /etc/dns-unified/keys/dnstt.key
```

The server forwards tunneled TCP streams by default to **127.0.0.1:22** (existing SSH daemon); ensure you intend this. The client needs the public key. Some forks use different CLI syntax. The example targets versions with `dnstt-server -udp :53 -privkey-file FILE DOMAIN UPSTREAMADDR`.

### SlipStream Rust (v0.2)

The `slipstream` engine ID now runs **Mygod/slipstream-rust**, not the older C implementation. We deliberately install as `slipstream-rust-server` and `slipstream-rust-client` to avoid binary collisions. The source repository was archived on **August 28, 2026**; it is optional, not automatically updated, and should be audited before use. For exact build steps, TLS, and client instructions see [RUST_SLIPSTREAM.md](docs/RUST_SLIPSTREAM.md).

After inspecting the included scripts on a Debian/Ubuntu VPS, run as a **normal sudo-capable user**:

```bash
bash scripts/install-slipstream-rust.sh
sudo bash scripts/prepare-slipstream-rust.sh
```

This installs the Rust binaries, creates a pinned TLS certificate and reset seed, and lets the panel use these validated server options: domain, DNS listen host, UDP listen port, local TCP target, max QUIC connections, idle timeout. The panel also stores **client-side templates** for resolver lists, authoritative endpoints, congestion control, keep-alive and local TCP port; it does not execute the client on your PC.

To make a SOCKS5 endpoint for browser or v2rayN use, the client tunnel needs a TCP target that runs a SOCKS5 server or an SSH daemon. The initial default is local VPS SSH `127.0.0.1:22`. See the Rust document for SSH dynamic forwarding.


### iodine

Install `iodined`. Write a strong password to `/etc/dns-unified/keys/iodine.pass` (mode 600). The adapter starts `iodined` with a `-P` password argument; this **can appear in process listings** to privileged local processes. iodine is **not encrypted**, so add SSH/VPN inside the tunnel before sending sensitive traffic. It provides a TUN interface rather than a SOCKS proxy; server-side NAT and safe routing are not automatically configured.

### dns2tcp

Install `dns2tcpd`. Write a shared key to `/etc/dns-unified/keys/dns2tcp.key` (mode 600). The manager generates a config and runs `dns2tcpd -F -f /etc/dns-unified/engines/dns2tcp/server.conf`, forwarding an `ssh` resource to 127.0.0.1:22. dns2tcp is **not encrypted**, so use SSH or another secure upstream. Confirm `dns2tcpd -f` behavior in the packaged version.

## Operations

- Dashboard: `http://127.0.0.1:8088` from SSH forwarded client.
- `Engines`: select active server engine; stop other `dns-unified@*.service` units.
- `Settings`: allowlisted settings saved to `/etc/dns-unified/profiles.json`; editing does not silently restart an active engine.
- `Monitoring`: CPU, RAM, disk, total VPS interface traffic counters (not per-tunnel throughput), socket listeners, and systemd health.
- `Logs`: latest 60 journal lines for each engine and history in `/var/lib/dns-unified/audit.jsonl`.
- Terminal checks: `sudo systemctl status dns-unified@master` and `sudo journalctl -u dns-unified-agent.service -n 100`.

The port check tests **TCP and UDP** listeners conservatively. Some engines (including some MasterDnsVPN distributions) may also use TCP 53; inspect with `ss -lntup` if needed. The manager does **not** install firewall rules or disable system DNS services.

**Switch semantics:** preflight → stop all DNS Unified tunnel units → verify UDP port free → start target → check systemd active after 400ms → attempt rollback if it failed. This verifies **systemd process health**, **not real DNS reachability**. If switching fails after configuration changed, rollback is best-effort. Always keep independent SSH or VPS console access. Do not expect live TCP connections to survive switching. If the client is also switching, change its mode separately; this package does not remotely orchestrate the client.

**Password reset:** `sudo /opt/dns-unified-control/.venv/bin/python -m duc.set_password` (run from `/opt/dns-unified-control`); restart the web service after a reset to invalidate existing sessions. Sessions are kept in memory, same-site HttpOnly cookies and CSRF are enforced, per-IP login failures are throttled. Use HTTPS for any public deployment.

## Tests

```bash
python3 -m pytest -q tests
python3 -m compileall -q duc
```

This project includes mock tests for rollback, exclusivity, validation, and runner argument generation; running tests does **not** start any tunnel.

## Upstream references

- [MasterDnsVPN](https://github.com/masterking32/MasterDnsVPN)
- [SlipStream Rust](https://github.com/Mygod/slipstream-rust) and [Rust CLI usage](https://github.com/Mygod/slipstream-rust/blob/main/docs/usage.md) (archived August 2026)
- [DNSTT](https://github.com/net2share/dnstt) and [original](https://www.bamsoftware.com/software/dnstt/)
- [iodine](https://github.com/yarrick/iodine)
- [dns2tcp](https://github.com/alex-sector/dns2tcp)
- [dnstm](https://github.com/net2share/dnstm)

## Known limitations / roadmap

1. No binary auto-installer, automatic key exchange, or end-to-end client-server synchronization.
2. Full client-side SOCKS/TUN management and resolver tests are a separate phase.
3. No packet-level RTT, DNS queries/s, resolver-specific loss/retransmits, or genuine throughput metrics yet.
4. DoH/DoT/DoQ adapters are not implemented. Avoid treating a DNS resolver transport as a universal VPN protocol.
5. No scheduler for automatic tunnel failover in this MVP.
6. Port ownership and IPv6/TCP conflicts need additional tests on the actual VPS; a production rollout should add nftables/iptables safeguards and integration tests.

Advanced architecture and public HTTPS notes: `docs/ARCHITECTURE.md`, `docs/PUBLIC_HTTPS.md`.

## Cloudflare API automatic DNS setup (v0.3)

**Prerequisite:** Transfer your domain to Cloudflare DNS management (add its zone and point the registrar's nameservers to Cloudflare). Merely buying the domain at Hostinger does not make Cloudflare authoritative. Cloudflare outgoing subdomain delegation is available on Free plans.

During `sudo bash install.sh`, choose **yes** at the Cloudflare DNS step. The one-shot command can also be run later:

```bash
sudo env PYTHONPATH=/opt/dns-unified-control /opt/dns-unified-control/.venv/bin/python -m duc.cloudflare_dns --domain akr.cfd
# Or supply an explicit external IPv4:
sudo env PYTHONPATH=/opt/dns-unified-control /opt/dns-unified-control/.venv/bin/python -m duc.cloudflare_dns --domain akr.cfd --ip YOUR_PUBLIC_IPV4
```

The CLI auto-detects the external IPv4 via `https://api.ipify.org` if `--ip` is omitted, shows the resulting records, asks for confirmation, and requests the token **without echoing input**. Do not pass tokens as shell arguments or write them into configuration files. Create a **zone-scoped token** with `Zone → Zone → Read` and `Zone → DNS → Edit` permissions, restricted to your selected Cloudflare zone. No global API key is necessary.

For `akr.cfd`, the CLI provisions `ns.akr.cfd A VPS_IPV4` (DNS only, never proxied), and `v.akr.cfd NS ns.akr.cfd`, then sets `v.akr.cfd` as the domain in all five server profiles. Because **Exclusive Mode** uses a single tunnel at any instant, you do not need five separate delegated subdomains. You can change labels with `--ns-label` and `--tunnel-label`.

The operation is repeatable: exact matches are kept; updates are only allowed for records tagged with the project management comment; records owned by someone else, mixed types and multiple NS targets cause an error rather than being overwritten. Existing records are preflight checked before changes, but API writes are not atomic: if the second write fails, the first may already have been created. Examine Cloudflare's DNS records and retry safely.

A `--dry-run` option shows the proposed operations without writing; it still authenticates to read the zone. `--no-profile-update` prevents editing engine domain profiles.

This **does not** install a tunnel server, expose/open UDP 53, prove that DNS delegation works from external resolvers, or guarantee Cloudflare NS/registrar updates; test those independently. Cloudflare's HTTPS proxy should not be used for the authoritative DNS `A` record.
