# 0.10.5 — Web installation completion gate

- TUI/local runtime and Web have independent completion status. Only trusted HTTPS/SNI-to-panel, valid certificate, renewable credentials and panel A matching instance mark Web READY.
- `sudo bash install.sh` incorporates Cloudflare DNS-01 certificate onboarding after local health, including on same-version repairs. Skipping it does not undo a working TUI, but the Web component is INCOMPLETE.
- Certificate renewal configuration is checked for a non-existing temporary Cloudflare credential path, a known 0.10.4 defect.
- Cloudflare NS tunnel cutover remains independent and guarded. Existing Xray/HAProxy listeners are never stopped or overwritten by the installer.
- Tests for component status, issuance prompts and broken renewal paths.
