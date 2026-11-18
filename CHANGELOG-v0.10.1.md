# v0.10.1 — Guided Product Installer

- Product default `install.sh` and bare `fresh-install.sh` now run the **preflight first** and step-by-step guided installation; no mandatory `--domain` or `--ip` flags.
- Existing automated flows (`--audit`, `--install`, `--postcheck`, `--resume`) remain available. Internal upgrade/install entrypoint explicitly guards against bypassing preflight.
- Read-only audit can run before domain/IP input; detects conflicting TCP/1080,8088 and non-loopback UDP/53 (blocking), reports local DNS stubs, memory/swap, and HTTPS port occupancy as warnings.
- Guided wizard validates domain and public IPv4, optionally checks Cloudflare Zone Read using a hidden ephemeral token, and never modifies Cloudflare records during installation.
- Optional 2 GiB local swap allocation on low-memory VPS requires explicit consent and happens only after final install confirmation.
- Conflicts and risks are printed before the first mutation; newly created Instance identity protects against wrong-host Resume.
- Tested offline only; production deployment, Cloudflare cutover and DNS tunnel E2E remain separate tests.
