# v0.9.1 — Soar Web Provision + Restricted Shared Dante

- Added restricted `duc-soar-server` built against audited official getlantern/soar Go library. Per-stream `Dial` refuses anything except `tcp 127.0.0.1:1080`.
- Added panel-controlled Soar installation, automatic idempotent Ed25519 keypair creation (strict private file permissions, no API secrets), Soar health/status, buildable downloadable Linux amd64 Soar-native Go client, and client command with port 2080 and existing Dante auth.
- Integrated into existing Exclusive Mode jobs and authenticated download routes, without changing UDP/53 or running engine during upgrade.
- No new client-side gateway, JSON setup, extra proxy listener, or credentials in the client ZIP.
- Existing public-destination `soar-server` is NOT used by the Soar runner. Legacy `soar.public-proxy-ack` not required.
- Kept the existing per-engine workflows and availability limits for the other engines; did not claim full nine-engine provisioning completed.
- v0.9.1 Soar backend is deliberately fixed to shared authenticated Dante only; custom Soar backend addresses disallowed until separately audited.
- Unit tests are not a substitute for compilation against upstream Go and real DNS tunnel verification on the actual VPS.
