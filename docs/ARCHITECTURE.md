# Architecture and state machine

```
Administrator browser
    |
    | ssh -L 8088:127.0.0.1:8088 VPS
    v
127.0.0.1:8088 — FastAPI web (User: dns-unified)
    | Login via PBKDF2; session cookie + CSRF; HTTP API
    | HTTP over Unix domain socket (mode 0660, group dns-unified)
    v
/run/dns-unified-agent.sock — Agent (root)
    | Restricted API: list, save approved fields, switch approved engine, logs
    v
/etc/dns-unified/profiles.json — root-owned server settings
    | start/stop only dns-unified@{master,slipstream,dnstt,noizdns,vaydns,soar,iodine,dns2tcp,xdns}.service
    v
systemd -> python -m duc.runner <engine> -> trusted upstream binary
    |
    v
Authoritative DNS interface UDP/TCP 53 on VPS
    ^
    | DNS resolvers, client-specific tunnel packets
    |
Linux personal client (client app configured independently)
```

## Switching sequence

1. Acquire exclusive advisory file lock (shared by profile updates and switch).
2. Check configured binary, non-placeholder domain, and root-owned secrets/template prerequisites.
3. List active manager-controlled systemd units, stop every old unit.
4. Inspect target DNS port listeners (both TCP and UDP); fail closed if port is occupied.
5. Start selected unit and ensure it stays active for a minimum stabilization interval.
6. On failure: stop failed unit and attempt to restore previous units. Audit result.
7. Return a warning: systemd activity does not prove end-to-end connectivity.

No custom systemd unit or arbitrary binary path is editable from the web. Only named fields are validated and saved. The engine runner builds a fixed `execv()` argument vector, without shell evaluation.

## Panel controls by engine

| Engine | Editable settings | Root-managed dependencies |
|---|---|---|
| MasterDnsVPN | domain, UDP port, ARQ window, log level, encryption method 2–5 | `server_config.toml.simple` copied as base, shared key |
| SlipStream | domain, UDP port, localhost TCP target | installed server binary |
| DNSTT | domain, UDP port, localhost TCP target | server private key |
| iodine | domain, UDP port, internal TUN IPv4 | password file; elevated TUN/NAT setup |
| dns2tcp | domain, UDP port, localhost TCP target, resource name | shared key file |

DoH/DoT/DoQ are not part of server adapters yet. TXT and CNAME are not independent engine processes. Future client profiles may expose `iodine -T TXT` etc., but server cannot force a specific query type for all clients.

## Monitor definitions

- CPU, RAM, disk are from psutil, system-wide.
- Network rates are deltas of psutil *system-wide* cumulative byte counters, not the tunnel throughput.
- Active engine PID, RSS, CPU% are sampled via psutil.Process where available.
- Port occupancy from `ss -H -lntu` is a local socket-listening signal.
- Engine health is `systemctl` activity, not resolver reachability.
- Event log is append-only JSONL stored at `/var/lib/dns-unified/audit.jsonl`.
- Journal tail is 60 lines per engine; secrets must not be intentionally emitted by engine programs.

## Further milestones

1. Client agent on Linux that can select exact same engine and authenticate via a separate management channel.
2. Two-phase prepare/commit for cross-host switches, with safe fallback if the client cannot reach the panel.
3. DNS authoritative domain verification (A and NS) and per-resolver reachability probes from the **client network**.
4. Engine exporter adapters (ARQ resend counters, DNS queries/s, packet loss, tunnel throughput), with explicit provenance; avoid inventing metrics.
5. Configuration migration/versioning, encrypted backups, more integration tests with Linux network namespaces and controlled packet loss.
6. Optional TUN output and v2rayN integration on the client, independent of this VPS-only dashboard.

## Threat model

Remote attackers must not access an HTTP port without TLS. The web service is unprivileged and only binds 127.0.0.1 by default, accessible over SSH port forwarding. The privileged agent receives commands only through a root-owned systemd Unix socket accessible to the `dns-unified` group. Every engine is allowlisted. All settings reject unexpected keys, paths, and arbitrary shell command fields.

No public write-only API; all API endpoints require session authentication; POST calls require CSRF. Strong passwords (>=16 chars) are PBKDF2-hashed with a random salt. Sessions reside in memory and are not portable across restarts; after changing the password, restart the web service to invalidate existing sessions.

This is an MVP, not a verified penetration-tested application. If exposed publicly add TLS, IP filtering, rate limits at reverse proxy, session persistence/invalidation, better per-request audit, and apply least-privilege capabilities to each engine unit.


## v0.4 independent records

Nine logical engines are registered through `duc.catalog`: stable IDs, labels, family names and methods. Cloudflare record provisioning is one shared unproxied A record plus nine independent NS delegations. Changing the active systemd unit never changes Cloudflare DNS records. Service checks are local only; DNS delegation checks are external and not synonymous with tested client ↔ DNS ↔ VPS tunneling.
