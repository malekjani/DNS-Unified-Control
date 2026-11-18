# 0.9.2 — Soar server installation corrected

- `install.sh` and `upgrade.sh` automatically and synchronously provision restricted `duc-soar-server` and generate/verify `soar.key` (0600) and `soar.pub` (derived Ed25519 key). The server provisioning step is no longer a button in the web client workflow.
- Uses existing resumable `duc.provision` installer with existing source verification, toolchain and lock. Installation nonzero-exits on failure and shows a specific error. No auto-start or Exclusive Mode switch, no Dante restart, no secret rotation.
- Client creation/download remains a web-panel action. Restricted fixed Dante backend stays unchanged.
- Old 0.9.1 guide kept as historical reference; see docs/V092_SOAR_INSTALL_FA.md for current behavior.
- A successful asset bootstrap does not itself certify DNS delegation or live tunnel connectivity.
