# DNS Unified Control v0.9.5 — SlipNet NoizDNS CLI release fix

- Fix **failed** NoizDNS client build (`Official release does not contain the exact slipnet-linux-amd64 asset`). Previous v0.9.4 selected `v2.5.5` which does not provide the expected exact Linux CLI asset.
- Select immutable upstream `v2.5.3 - CLI` and exact asset `slipnet-linux-amd64` confirmed at https://github.com/anonvector/SlipNet/releases/tag/v2.5.3 .
- Pin binary digest `1eb6a66df7a9d15e2260dd28d28655a3d5cebced8504509062ab614097f27534`, as published on the SourceForge project mirror. It is **not** an upstream signature or independent authenticity attestation. Download only via fixed HTTPS links: GitHub release first, SourceForge mirror only if GitHub download fails; verify ELF signature, size and SHA-256 in both cases. Any checksum mismatch aborts.
- Do not rely on GitHub's `latest` release or API `digest` field (which is missing or release-specific).
- Keep NoizDNS server, keys, active engine, Dante, 2FA, DNS delegation and all prior engines unchanged during upgrade.
- No extra Python client gateway or client JSON. Native SlipNet still has local SOCKS implementation; Dante pass-through/injection remains subject to field verification.
- Test run is a mocked download/integrity test, not an actual network download or VPS test.
