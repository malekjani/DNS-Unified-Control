# DNS Unified Control v0.10.6 — Multi-Engine Core Integration (P1)

This is the full integrated source release built from verified v0.10.5 Web Completion Gate, not an add-on patch. **No live 7-engine compatibility is claimed.**

- Integrated `ducmulti` package and web assets directly into existing Web, Agent, and TUI, preserving MFA/CSRF and the common Unix Agent.
- `install.sh` installs the two new systemd unit templates but does **not start/enable** them or change active DNS engine, Cloudflare, public TLS, Xray, HAProxy or Dante.
- Existing Exclusive Mode is preserved and guarded against competing legacy switch operations while Multi is active.
- Added opt-in Multi mode with domain-based DNS query forwarding via UDP/TCP port 53 on local interface IPv4, loopback engine backend ports, preflight, yes/no confirmation and best-effort rollback.
- Lifecycle snapshots contain installed Multi unit files for subsequent upgrades.
- CottenDNS requires a separately vetted loopback adapter; with seven engines selected, preflight will refuse activation until its configuration and SlipStream/other dependencies are ready.
- Mode switching is not part of upgrade/install lifecycle and requires deliberate explicit action by an authorized administrator.
- Limitations: no on-VPS field test, no live failover, no automated CottenDNS provisioning, no production throughput guarantee, no ACID rollback on power loss, no implicit Web TLS/DNS cutover.

## Install / upgrade

```
cd /root
unzip -tq DNS-Unified-Control-v0.10.6-Multi-Engine-P1-Integrated.zip && unzip -oq DNS-Unified-Control-v0.10.6-Multi-Engine-P1-Integrated.zip
cd dns-unified-control
python3 scripts/verify-release.py
sudo bash install.sh --dry-run
sudo bash install.sh
```

After the upgrade, a **read-only** status and plan:

```
sudo /opt/dns-unified-control/.venv/bin/python -m ducmulti.cli status
sudo /opt/dns-unified-control/.venv/bin/python -m ducmulti.cli plan --mode multi --engines master,soar,cotten,slipstream,noizdns,dnstt,vaydns
```

To access: Web → Exclusive / Multi, or `python -m duc.tui` → menu 9. Readiness must pass before switching. Do not use `apply` on a production server until the router is validated with a controlled client field test and console rollback.
