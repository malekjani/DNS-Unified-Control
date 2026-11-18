# Upstream engines, sources, and scope of integration (2026-11)

All rights remain with upstream maintainers. This project installs or controls third-party binaries without bundling their code; review each upstream license and release before redistributing.

| Engine | Upstream | Driver | Caution |
|---|---|---|---|
| MasterDnsVPN | https://github.com/masterking32/MasterDnsVPN | TOML | Key format / Go version-specific |
| SlipStream Rust | https://github.com/Mygod/slipstream-rust | CLI | Repository archived Aug 2026 |
| DNSTT | https://github.com/net2share/dnstt | CLI | Noise private/public keys |
| NoizDNS | https://github.com/anonvector/noizdns-deploy and https://github.com/SamNet-dev/dnstm-setup | CLI conditional | Fork's PT or -udp version must be checked |
| VayDNS | https://github.com/net2share/vaydns | CLI | DoH/DoT client support; `-dnstt-compat` matching |
| Soar | https://github.com/getlantern/soar | CLI | Pre-release; direct server exposes allowed port proxy to key holders |
| iodine | https://github.com/yarrick/iodine | CLI | TUN and no encryption by default |
| dns2tcp | https://github.com/alex-sector/dns2tcp | CLI | TCP forwarding; SSH/TLS recommended |
| XDNS | https://xtls.github.io/en/config/transports/finalmask.html | Xray native config | Not a standalone binary; mKCP compatible only |

The installer builds open-source engines from head of corresponding repositories or fetches official GitHub release binaries. It is therefore **not reproducible or checksum-pinned** yet. Production use should pin commits/releases and verify signatures/checksums.

The SamNet-dev dnstm-setup project's DNS record layout was used as a cross-check for NS delegation of NoizDNS and VayDNS; this project is **not** a fork of dnstm and does not run dnstm's shared DNS Router. Its architecture remains exclusive single-engine UDP port 53.
