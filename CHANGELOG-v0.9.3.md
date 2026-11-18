# v0.9.3 — NoizDNS server auto-provision

- Installer and upgrader always install a separate native NoizDNS server from `anonvector/dnstt` (`noizdns-server`), preserving regular `dnstt-server`.
- Track Go source commit and SHA256 to detect untrusted binaries; rebuild unverified old binaries.
- Generate/check isolated Noise keypair at `/etc/dns-unified/keys/noizdns.{key,pub}`; private mode 0600, no key rotation.
- Read-only key derivation consistency check; no keys/passwords in client APIs.
- Old NoizDNS default backend `127.0.0.1:22` migrates to authenticated shared Dante on `127.0.0.1:1080` (backs up previous target). Custom targets remain untouched.
- No DNS tunnel switch, UDP/53 restart, firewall, systemd-resolved, Caddy or Dante restart during provisioning.
- NoizDNS is now one of the audited server-side raw TCP engines for shared Dante configuration.
- Client export stays explicitly unsupported for Linux NoizDNS stealth mode until tested native implementation is available. No Gateway or JSON client setup is introduced.
- Installing server from source requires reaching GitHub and compiling Go on the VPS; failure is fatal to installer while pre-existing DNS engine remains active.
