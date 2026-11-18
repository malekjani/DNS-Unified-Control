# DNS Unified Control v0.9.7 — review fixes

- Client build jobs now accept validated `resolver` (public IPv4:53) and `port` (local TCP 1024..65535).
- Persist the same build settings through Web -> Agent -> Job -> Worker -> ZIP and surface them in job state for TUI.
- Native NoizDNS SlipNet and alternate SlipNet/DNSTT launchers use the selected build resolver/port by default and explicit `--dns` for recursive transport.
- Old NoizDNS and alternate ZIPs are `stale` until rebuilt; no server daemon is switched by a build.
- User interface refuses to label a ZIP built for a different resolver/port as the currently selected ready package.
- Native DNSTT guide uses the bundled `server.pub` with `-pubkey-file`, matching the verified client usage.
- Existing Dante credentials, DNS delegation, keypairs, and exclusive running engine are unchanged.

No live VPS upgrade or alternative VayDNS/DNSTT SlipNet end-to-end test was performed.
