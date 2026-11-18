# Optional HTTPS control panel — separate Cloudflare DNS record

For a zone like `akr.cfd` **only if you own and have activated the zone in Cloudflare**, the panel runs at `https://panel.akr.cfd` while the authoritative DNS tunnel names remain on their own `NS` delegations.

| Record | DNS hostname | Content | Cloudflare Proxy |
|---|---|---|---|
| A | `ns.akr.cfd` | public VPS IPv4 | DNS only |
| NS | `m.akr.cfd` … `x.akr.cfd` | `ns.akr.cfd` | Not applicable |
| **A** | **`panel.akr.cfd`** | public VPS IPv4 | **DNS only** (for initial Let's Encrypt setup) |

**IMPORTANT:** the control-panel A record must NOT be delegated to the tunnel nameserver, and the panel is separate from DNS-over-HTTPS tunneling. It does not use UDP port 53.

## Deploy (Debian / Ubuntu, root)

1. Install/upgrade DNS Unified Control first: `sudo bash install.sh`.
2. Run `sudo bash scripts/setup-panel-https.sh` interactively. Enter Cloudflare zone, optional label, VPS IPv4 (or autodetect), and a **zone-scoped Cloudflare API token** with Zone Read and DNS Edit. The token is hidden and discarded after use.
3. Review the exact record and approve. Declining aborts the rest of HTTPS setup; the script refuses to overwrite unrelated DNS records.
4. The script installs distro `caddy` if needed, validates its Caddyfile, preserves a backup and enables `DUC_COOKIE_SECURE=1` and `DUC_TRUST_LOCAL_PROXY=1` for the web backend.
5. Allow inbound **TCP 80 and TCP 443**, with no effect on your existing UDP rules. Ensure no other web server occupies them. Caddy uses ACME to obtain and automatically renew a public certificate. HTTP/3 is disabled to keep **UDP 443** unused.
6. Check `sudo journalctl -u caddy -n 70 --no-pager` and `curl -I https://panel.YOUR_DOMAIN`. The first TLS issuance depends on DNS propagation and TCP reachability, and is **not guaranteed by a successful script exit**.

The script will refuse to overwrite another Caddy application or unexpected listener. For an existing Caddy deployment, manually **add** this site to your maintained Caddyfile (and ensure the global `servers :443 { protocols h1 h2 }` setting if you want UDP 443 unused):

```caddyfile
panel.example.com {
    encode zstd gzip
    header Strict-Transport-Security "max-age=2592000"
    header X-Content-Type-Options "nosniff"
    reverse_proxy 127.0.0.1:8088 {
        header_up X-DUC-Client-IP {remote_host}
    }
}
```

Do not serve port 8088 publicly: FastAPI should remain on `127.0.0.1:8088`. An optional systemd override makes cookies Secure; otherwise on non-HTTPS access the browser may reject login session cookies. To revert panel TLS mode safely:

```bash
sudo rm -f /etc/systemd/system/dns-unified-web.service.d/https.conf
sudo systemctl daemon-reload
sudo systemctl restart dns-unified-web.service
```

This does not remove records, Caddy, or any tunnel engine; removal should be manual and deliberate.

## Security considerations

- HTTPS only encrypts the transport; **it does not stop unauthorized login attempts**. For a privileged network panel, prefer an IP allowlist or Cloudflare Zero Trust Access plus strong unique app password.
- If using Cloudflare Access, switch `panel` to proxied and enable **Full (strict)** TLS, create a self-hosted Access application and deny-by-default policy. **Guard the origin against bypass** (IP allowlist of Cloudflare egress or Cloudflare Tunnel); otherwise a direct request to the public VPS IPv4 may bypass Access.
- The project does not automatically enable Cloudflare Access, create or store Access credentials, or modify firewall rules. Existing SSH management must remain reachable independently of any DNS tunnel.
- Cloudflare API token is never written to project files. Caddy's ACME certificate and private key are stored by Caddy in its protected data directory.
- Never proxy the delegated DNS labels (`m`, `r`, `d`, etc.) through Cloudflare HTTP; they remain NS delegation records.
- For private use, SSH port forwarding to `http://127.0.0.1:8088` remains the lowest-exposure alternative, even though the public HTTPS option is available.
