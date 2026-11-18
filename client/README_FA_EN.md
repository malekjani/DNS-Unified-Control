# DUC Native Client — no local Gateway

Only run the selected DNS tunnel client, bind its raw-TCP listener to
`127.0.0.1:2080`, and use the **same username/password as shared Dante** in
v2rayN/FoxyProxy. Dante binds ONLY 127.0.0.1:1080 on the server.

v2rayN URI is generated **on VPS only** (root, private):
`PYTHONPATH=/opt/dns-unified-control /opt/dns-unified-control/.venv/bin/python -m duc.unified link`

Passwords are Base64-encoded in SOCKS URLs and can be decoded by anyone who
sees the URL. Keep it private. No private credentials are exported to this ZIP.

SlipStream example (run from downloaded binary/cert directory):
`./slipstream-rust-client -r 1.1.1.1:53 -d r.YOUR_DOMAIN -l 2080 --cert ./slipstream-rust.crt`

DNSTT and VayDNS require matching client binaries and server public keys.
Always stop the preceding tunnel client before binding port 2080.

Test the actual SOCKS connection using `duc_socks_probe.py`:
`python3 duc_socks_probe.py --engine slipstream --repeat 4 --out report.json`
It asks for the Dante password without echoing it. On a clean Debian machine
this script uses Python standard library only. HTTP success/failure ratio is
**not** raw DNS packet loss. Upload/import reports securely with:
`python -m duc.telemetry import /root/report.json`

DNS2TCP: credentials would traverse DNS without encryption. Do NOT forward
Dante in plaintext; retain SSH as backend unless an authenticated encrypted
wrapper is provided and verified.

SOAR: its server dials public destinations, not local Dante by default.
Iodine: IP-over-DNS requires a network/tun adapter and does not speak SOCKS.
NoizDNS/XDNS: per-release compatibility checks remain required.
