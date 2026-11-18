# Experimental Multipath Bonding (P0)

This branch keeps `main` at v0.10.6 and adds an isolated Go proof of concept for multipath TCP-stream striping under [`experiments/multipath-p0/`](experiments/multipath-p0/README_FA.md).

**Not production-ready. Do not attach to a live DNS tunnel or switch an operating DUC server to this relay.** This prototype needs separate, compatible raw-TCP DNS tunnel forwarding into the relay. It does not manage or provision engine binaries, routing, Cloudflare, or server credentials.

## Verify locally

```bash
cd experiments/multipath-p0
go test ./...
go test -race ./...
go vet ./...
go build -trimpath -o duc-multi ./cmd/duc-multi
```

P0 demonstrates two TCP paths exchanging one SOCKS5 CONNECT stream with bidirectional framing and reassembly. It does **not** support path-loss recovery, retransmission, adaptive scheduling, production quotas, or application-level encrypted data frames. See the [Persian guide](experiments/multipath-p0/README_FA.md) for details.

When a field-ready implementation is developed, integrate it behind a separate opt-in mode with rigorous preflight, authentication, rollback, independent client/server transports, and real DNS-client interoperability tests.
