# Security policy

- Do not commit VPS credentials, Cloudflare tokens, private keys, TOTP seeds, or backups.
- Keep `/etc/dns-unified`, `/var/lib/dns-unified`, and `/var/backups/dns-unified` out of the repository.
- Use private security reports instead of public issues for vulnerabilities.
- Do not run DNS/HTTPS cutover until the relevant health checks succeed.
- v0.10.6 Multi-Engine is a P1/preflight release; seven-engine production compatibility is not yet field-verified.
