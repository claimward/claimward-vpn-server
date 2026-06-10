# claimward-vpn-server

[![Go Reference](https://pkg.go.dev/badge/github.com/claimward/claimward-vpn-server.svg)](https://pkg.go.dev/github.com/claimward/claimward-vpn-server) [![Go Report Card](https://goreportcard.com/badge/github.com/claimward/claimward-vpn-server)](https://goreportcard.com/report/github.com/claimward/claimward-vpn-server) [![License: BSD-3-Clause](https://img.shields.io/badge/License-BSD--3--Clause-blue.svg)](LICENSE)

Control plane for the Claimward VPN. It authenticates devices with **OIDC** and
programs a **WireGuard** gateway, one peer per enrolled device.

Designed to run co-located on the Linux gateway host: it manages *peers* on an
existing `wg0` interface via `wgctrl` (the interface itself is created by
wg-quick/systemd at boot).

## Endpoints

All requests carry the user's OIDC ID token as `Authorization: Bearer <id_token>`.
Shapes are defined in [`claimward-vpn-client/pkg/protocol`](https://github.com/claimward/claimward-vpn-client) — the single shared source of truth.

| Method & path | Purpose |
|---------------|---------|
| `POST /api/v1/enroll` | Verify token, allocate an IP, add the WireGuard peer, return tunnel config |
| `POST /api/v1/heartbeat` | Renew the device's lease |
| `POST /api/v1/deregister` | Remove the peer |
| `GET /healthz` | Liveness |

## Flow

```
client --Bearer id_token + wg pubkey--> /enroll
  ├─ auth.Verify        verify token (issuer discovery) + email-domain allowlist
  ├─ ipam.Allocate      next free address from VPN_CIDR (server takes .1)
  ├─ wg.AddPeer         wgctrl: add peer with AllowedIPs = clientIP/32
  └─ store.Put          remember the lease
client <-- assigned IP, server pubkey, endpoint, routes, DNS, keepalive --
```

A background reaper removes peers whose lease expired (no heartbeat).

## Configuration (environment)

| Var | Required | Default | Notes |
|-----|----------|---------|-------|
| `OIDC_ISSUER` | ✅ | — | issuer URL (discovery) |
| `OIDC_CLIENT_ID` | ✅ | — | expected token audience |
| `OIDC_ALLOWED_DOMAINS` | | — | CSV email-domain allowlist |
| `WG_ENDPOINT` | ✅ | — | public `host:port` advertised to clients |
| `WG_PRIVATE_KEY` / `WG_PRIVATE_KEY_FILE` | ✅ | — | base64 server key |
| `WG_INTERFACE` | | `wg0` | kernel interface to manage |
| `WG_DRYRUN` | | `false` | log peer ops instead of applying — local dev |
| `VPN_CIDR` | | `10.80.0.0/24` | address pool; `.1` is the gateway |
| `PUSH_ROUTES` | | `VPN_CIDR` | CSV AllowedIPs pushed to clients |
| `DNS` | | — | CSV DNS servers pushed to clients |
| `KEEPALIVE` | | `25` | persistent keepalive (seconds) |
| `LEASE_TTL` | | `24h` | lease duration without heartbeat |
| `LISTEN_ADDR` | | `:8443` | |
| `TLS_CERT` / `TLS_KEY` | | — | enable HTTPS; otherwise terminate TLS at a proxy |

## Run locally (no WireGuard device needed)

```sh
export OIDC_ISSUER=https://accounts.google.com
export OIDC_CLIENT_ID=xxxx.apps.googleusercontent.com
export WG_ENDPOINT=vpn.example.com:51820
export WG_PRIVATE_KEY=$(wg genkey)
export WG_DRYRUN=true LISTEN_ADDR=:8080

go run ./cmd/claimward-server
```

## License

BSD 3-Clause — see [LICENSE](LICENSE).
