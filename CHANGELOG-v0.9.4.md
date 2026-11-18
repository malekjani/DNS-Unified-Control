# DNS Unified Control v0.9.4 — SlipNet NoizDNS Stealth integration

- Server installer unchanged: idempotent independent `noizdns-server` from `anonvector/dnstt`, Ed25519/X25519 keys and Dante loopback backend.
- NoizDNS build-client job now fetches an exact official SlipNet CLI Linux amd64 release (`v2.5.5`), requires GitHub-provided SHA-256 digest, checks byte length/ELF/hash and refuses unexpected upstream URLs.
- Native SlipNet profile format uses `sayedns`, Noise server public key, NoizDNS Stealth flag at field 38, resolver, loopback listener 2080, no credentials. No JSON, no Python gateway, no client daemon.
- Client ZIP: native executable, public pipe-delimited config, a shell launcher, optional credential injection helper that only prompts on the user's computer, explicit security warning and documentation.
- Native upstream SlipNet includes its own in-process SOCKS5 handler; authentication may be injected to Dante instead of passed through from v2rayN. **This is not field-verified.** User must complete a real connectivity and credential test; don't mark as success based on unit tests.
- Running DNS engine, active SSH, Dante, Cloudflare, keys, and TOTP are unaffected by an upgrade.
