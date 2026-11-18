# DNS Unified Control 0.10.4 — Safe Public Onboarding Foundation

- Single installer now accepts **only explicit `yes`** to approve mutating actions; empty, `no`, `y`, bad input and EOF deny by default. Human prompts are yes/no only.
- New read-only public plan: `sudo bash install.sh --public-plan` reports exact instance DNS names and TCP 80/443 owners.
- DNS changes are NOT automatic during base installation. Guarded `--publish-panel` requires a valid trusted HTTPS route to the DUC login page on local 443. Guarded `--publish-ns --client-verified` requires local health plus two explicit yes confirmations, and changes the single authoritative nameserver A record only, never the NS delegations.
- Cloudflare tokens are re-entered at activation time and are never put in lifecycle journals. Read-only verification in first-install never saves a token.
- `--issue-cert-dns01` uses Certbot Cloudflare DNS-01 with a one-time token in root-only /run file, removed after the attempt; no interruption of Xray/HAProxy. Separate approval is required. Renewal needs a separate secret-management configuration.
- `--issue-cert-only` offers an explicitly disruptive certificate-only HTTP-01 fallback; tracks active HAProxy/Xray and restores them on success or failure. It neither configures reverse-proxy routing nor falsely reports HTTPS as ready.
- Public HTTPS checker now verifies a trusted certificate **and the DUC page** through local 443, regardless of TLS gateway brand.

Important: On existing hosts where Xray owns 443, simply stopping it temporarily to issue a certificate and restarting it does NOT publish the DUC panel. Configure SNI multiplexing or a dedicated TLS front end first. No automatic config edits to unrelated proxies are made.

No DNS or server changes were performed by building this release.
