# v0.10.0 — Portable Product Foundation

- Single-instance identity file `/etc/dns-unified/instance.json` with a generated UUID, domain and public IPv4; secret-free, permissions 0600.
- `--resume` now checks the original identity and refuses mismatched domains/IPs; never assumes the previously used domain.
- Fresh-install preflight requires an explicit domain, writes no DNS records and starts no UDP/53 engine.
- Cloudflare A-record cutover utility now requires explicit `--domain` and checks the expected old IP and DNS-only ownership before applying.
- Upgrade message reports instance-specific panel DNS rather than a fixed customer hostname.
- Core service paths under `/opt`, `/etc`, `/var/lib` remain package-defined in this release: per-instance **domain and IP are portable**, alternate filesystem prefixes and OS families are **not** supported yet.
- This update does not convert the current installer into an atomic package manager or certify engine builds across all operating systems.
