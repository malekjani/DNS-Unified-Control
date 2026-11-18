# SlipStream Rust — Client Options / گزینه‌های کلاینت

**Source:** AliRezaBeigy/slipstream-rust-deploy, pinned release `42e3e75`.
**DNS Unified Control v0.9.0:** NO extra client Gateway. Run SlipStream Rust Client directly on local port `2080`; with shared Dante on the VPS this port speaks authenticated SOCKS5. Older Gateway/22080 examples below, if any, are historical and not for v0.9.0. Examples refer to `r.m2m.diy` and the bundled `slipstream-rust-client` + `slipstream-rust.crt`.
**IMPORTANT:** A local TCP port is a **TCP forward**, NOT an automatic SOCKS5 or HTTP proxy. Server target in the current installation is `127.0.0.1:22` (SSH).

| Option | توضیح فارسی / English | Upstream default | Example |
|---|---|---|---|
| `--resolver`, `-r` | آدرس DNS **recursive** (e.g. Google or Cloudflare), repeatable for multipath; NOT necessarily the server's own IP | Required unless using authoritative | `--resolver 1.1.1.1:53` |
| `--authoritative` | آدرس **مستقیم خود DNS سرور** و نه Resolver عمومی؛ direct authoritative path | Optional | `--authoritative 188.132.174.249:53` |
| `--domain`, `-d` | دامنه واگذارشده به SlipStream / delegated tunnel zone | Required | `--domain r.m2m.diy` |
| `--tcp-listen-host` | آدرس گوش‌دادن کلاینت / local bind host; keep loopback unless intentional | `127.0.0.1` in DUC export | `--tcp-listen-host 127.0.0.1` |
| `--tcp-listen-port`, `-l` | پورت ورودی TCP محلی / raw TCP forward listen port | 5201 (upstream); DUC default 7000 | `--tcp-listen-port 2080` |
| `--cert` | گواهی **عمومی** سرور برای Pinning / public certificate (not the private key) | Optional upstream; required for DUC's pinned setup | `--cert ./slipstream-rust.crt` |
| `--congestion-control`, `-c` | انتخاب الگوریتم / `bbr`, `dcubic`; omit to keep release defaults | Auto / release selection | `--congestion-control bbr` |
| `--keep-alive-interval`, `-t` | فاصله بر حسب **میلی‌ثانیه** / interval in milliseconds | 400 ms | `--keep-alive-interval 400` |
| `--gso` | Generic Segmentation Offload, **not fully implemented** in this Rust client; leave off | Disabled | *Not recommended* |

## Using the Tunnel / استفاده از تونل

### A. SSH backend — CURRENT SERVER SETUP / وضعیت فعلی

**Server target:** `127.0.0.1:22`. The client listens locally at `127.0.0.1:2080`; it is **not a SOCKS proxy**.

```bash
cd ~/Downloads/slipstream-linux-amd64
./slipstream-rust-client --resolver 1.1.1.1:53 --domain r.m2m.diy --tcp-listen-host 127.0.0.1 --tcp-listen-port 2080 --cert ./slipstream-rust.crt --keep-alive-interval 400
```

In another terminal, use a REAL SSH client (client-first handshake), not `ssh-keyscan` alone:

```bash
ssh -vv -o BatchMode=yes -o PreferredAuthentications=none -o ConnectTimeout=30 -p 2080 root@127.0.0.1
```

If the output reaches `SSH2_MSG_NEWKEYS received`, the SSH handshake works even if it ends with `Permission denied` because authentication was deliberately disabled. A bare `ssh-keyscan` is **not sufficient** for this release; its server-first behavior timed out in observed tests.

To obtain authenticated SOCKS5 **through SSH**, only after confirming valid SSH credentials:

```bash
ssh -N -D 127.0.0.1:1080 -p 2080 YOUR_SSH_USER@127.0.0.1
curl -4 --max-time 60 --socks5-hostname 127.0.0.1:1080 https://api.ipify.org
```

### B. SOCKS5 backend — OPTIONAL, NOT INSTALLED BY THIS GUIDE

Provision an authenticated/ACL-restricted SOCKS5 service on the **VPS**, binding to loopback only, such as `127.0.0.1:1080`. After installing/configuring it separately, change the DUC SlipStream `target` to `127.0.0.1:1080` in the web panel and **explicitly restart/switch** the SlipStream engine via Exclusive Mode. Then start the client on Debian as above, and use `127.0.0.1:2080` as a SOCKS5 proxy:

```bash
curl -4 --max-time 60 --socks5-hostname 127.0.0.1:2080 https://api.ipify.org
```

**Security:** SlipStream certificate pinning authenticates the server to the client; it does NOT create SOCKS client authentication. An unauthenticated local-only SOCKS backend may become reachable to remote users through the publicly delegated DNS tunnel. Set authentication/ACLs and rate limiting before enabling it. DUC never auto-installs Dante or adds NAT/iptables rules in this update.

### C. Shadowsocks backend — OPTIONAL, NOT INSTALLED BY THIS GUIDE

Provision an authenticated Shadowsocks **TCP** server listening only at `127.0.0.1:8388` on the VPS, then configure SlipStream's `target` in DUC to `127.0.0.1:8388`, explicitly switch/restart through DUC. The SlipStream client still forwards **raw TCP** locally on port 2080; it does NOT create SOCKS5 by itself.

An `ss-local` client can reach the server **through that raw TCP forwarding port** (not through a nonexistent SlipStream SOCKS proxy). Example client config; use the SAME method/password as the separately configured server:

```json
{
  "server": "127.0.0.1",
  "server_port": 2080,
  "local_address": "127.0.0.1",
  "local_port": 10800,
  "password": "REPLACE_WITH_SECURE_SHADOWSOCKS_PASSWORD",
  "method": "aes-256-gcm"
}
```

```bash
ss-local -c ./ss-client.json
curl -4 --max-time 60 --socks5-hostname 127.0.0.1:10800 https://api.ipify.org
```

The upstream README example `slipstream-client --listen ...` / `ss-local --socks5-proxy ...` must **not** be copied directly into this Rust client setup: our tested CLI exposes `--tcp-listen-host` / `--tcp-listen-port`, and the endpoint is a raw TCP forward.

### Recursive vs Authoritative

- Recursive: `--resolver 1.1.1.1:53` (tests real delegated DNS transport).
- Direct authoritative: `--authoritative 188.132.174.249:53` (tests direct UDP reachability; may be blocked on some networks).
- Don't specify `--authoritative 1.1.1.1:53`: 1.1.1.1 is a recursive public resolver, not the authoritative VPS.
- More resolver paths are **not** automatically faster. Many paths failed during the observed 26-resolver test; prefer one proven path first.

### Server ownership / مالکیت سرویس

Do not run AliRezaBeigy's standalone deployment script on the DUC-managed VPS. Only `dns-unified@slipstream.service` is allowed to own UDP/53 when SlipStream is active. Current installation is SSH backend; mode change requires an existing local backend and an explicit engine restart in the DUC panel.
