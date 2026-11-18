# v0.9.0 Native SOCKS / Shared Dante

- Removed local SOCKS gateway code, public gateway download and secret setup JSON.
- Shared authenticated Dante is preferred for audited raw TCP forwarding engines: SlipStream, DNSTT, VayDNS.
- Custom loopback target/port or rollback per-engine; no new public port/service.
- Excluded dns2tcp from raw Dante (no transport encryption), and NoizDNS pending fork audit.
- Master native SOCKS port configurable in newly built client packages.
- Added actual VayDNS idle timeout, keepalive, KCP window, overflow, log-level settings and checked invariants.
- Added client-side SOCKS5/HTTPS authenticated probe (no credentials in report).
- Added iodine IP-level ping probe and 10-preset staged profile benchmark (from previous project).
- Added persisted field telemetry API and dashboard cards, with explicitly honest metric labels.
- Added server read-only field audit and advanced options registry.
- No independent DNS service, DNS mux, firewall, NAT or client gateway introduced.
- No real DNSTT/VayDNS/dns2tcp/Soar field test was conducted by the release builder on user's VPS.
- Remaining: pin actual NoizDNS variant and XDNS Xray configurations; per-engine raw DNS loss/throughput instrumentation.
