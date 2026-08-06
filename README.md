# claimward-vpn-server

[![Go Reference](https://pkg.go.dev/badge/github.com/claimward/claimward-vpn-server.svg)](https://pkg.go.dev/github.com/claimward/claimward-vpn-server) [![Go Report Card](https://goreportcard.com/badge/github.com/claimward/claimward-vpn-server)](https://goreportcard.com/report/github.com/claimward/claimward-vpn-server) [![License: BSD-3-Clause](https://img.shields.io/badge/License-BSD--3--Clause-blue.svg)](LICENSE)

Control plane for the Claimward VPN. It authenticates devices against a
pluggable identity provider — **GitHub** by default, or any **OIDC** issuer —
and programs a **WireGuard** gateway, one peer per enrolled device.

Designed to run co-located on the Linux gateway host: it manages *peers* on an
existing `wg0` interface via `wgctrl` (the interface itself is created by
wg-quick/systemd at boot).

## Endpoints

Enrollment requests carry the user's bearer credential as
`Authorization: Bearer <token>` — a **GitHub OAuth access token** (default
provider) or an **OIDC ID token** (`AUTH_PROVIDER=oidc`). Request/response
shapes are defined in
[`claimward-vpn-client/pkg/protocol`](https://github.com/claimward/claimward-vpn-client/tree/main/pkg/protocol)
— the single shared source of truth.

| Method & path | Purpose |
|---------------|---------|
| `POST /api/v1/enroll` | Verify token, allocate an IP, add the WireGuard peer, return tunnel config |
| `POST /api/v1/heartbeat` | Renew the device's lease |
| `POST /api/v1/deregister` | Remove the peer |
| `GET /healthz` | Liveness |

## Flow

```
client --Bearer token + wg pubkey--> /enroll
  ├─ verifier.Verify    resolve identity: GitHub API (+ org allowlist) or OIDC ID-token verification
  ├─ ipam.Allocate      next free address from VPN_CIDR (server takes .1)
  ├─ wg.AddPeer         wgctrl: add peer with AllowedIPs = clientIP/32
  └─ store.Put          remember the lease
client <-- assigned IP, server pubkey, endpoint, routes, DNS, keepalive --
```

A background reaper removes peers whose lease expired (no heartbeat).

## Other surfaces

Beyond the enrollment API, the server exposes:

- **RouteService (gRPC)** — a `Watch` stream (on `GRPC_ADDR`, default `:8444`;
  advertised to clients as `GRPC_ENDPOINT`) that pushes a client's tenant routes
  and live updates.
- **Admin API + WebUI** — a token-guarded (`ADMIN_TOKEN`) surface under `/admin/`:
  a `GET /admin/api/overview`, tenant CRUD at `/admin/api/tenants[...]`, and an
  embedded Svelte single-page app. Disabled unless `ADMIN_TOKEN` is set.
- **Prometheus metrics** — exposition at `/metrics`.

Routes are tenant-scoped: identities are mapped to tenants, and the RouteService
streams the routes for a client's tenant.

## Configuration (environment)

| Var | Required | Default | Notes |
|-----|----------|---------|-------|
| `AUTH_PROVIDER` | | `github` | identity provider: `github` or `oidc` |
| `GITHUB_ALLOWED_ORGS` | | — | CSV org-membership allowlist (github authz; recommended) |
| `GITHUB_API_URL` | | `https://api.github.com` | set for GitHub Enterprise |
| `OIDC_ISSUER` | when `oidc` | — | issuer URL (discovery) |
| `OIDC_CLIENT_ID` | when `oidc` | — | expected token audience |
| `OIDC_ALLOWED_DOMAINS` | | — | CSV email-domain allowlist (oidc authz) |
| `WG_ENDPOINT` | ✅ | — | public `host:port` advertised to clients |
| `WG_PRIVATE_KEY` / `WG_PRIVATE_KEY_FILE` | ✅ | — | base64 server key |
| `WG_INTERFACE` | | `wg0` | kernel interface to manage |
| `WG_DRYRUN` | | `false` | log peer ops instead of applying — local dev |
| `VPN_CIDR` | | `10.80.0.0/24` | address pool; `.1` is the gateway |
| `PUSH_ROUTES` | | `VPN_CIDR` | CSV AllowedIPs pushed to clients |
| `DNS` | | — | CSV DNS servers pushed to clients |
| `KEEPALIVE` | | `25` | persistent keepalive (seconds) |
| `LEASE_TTL` | | `24h` | lease duration without heartbeat |
| `LISTEN_ADDR` | | `:8443` | HTTP control-plane listen address |
| `GRPC_ADDR` | | `:8444` | RouteService gRPC listen address |
| `GRPC_ENDPOINT` | | — | `host:port` advertised to clients for route streaming |
| `ADMIN_TOKEN` | | — | bearer for the admin API/WebUI; empty disables admin |
| `TLS_CERT` / `TLS_KEY` | | — | enable HTTPS; otherwise terminate TLS at a proxy |

## Run locally (no WireGuard device needed)

The server is assembled and started from `cmd/claimward-server` (see
`Taskfile.yml` — `task start`). With `WG_DRYRUN=true` no real WireGuard device
is touched:

```sh
export AUTH_PROVIDER=oidc                                   # or default `github`
export OIDC_ISSUER=https://accounts.google.com
export OIDC_CLIENT_ID=xxxx.apps.googleusercontent.com
export WG_ENDPOINT=vpn.example.com:51820
export WG_PRIVATE_KEY=$(wg genkey)
export WG_DRYRUN=true LISTEN_ADDR=:8080

go run ./cmd/claimward-server
```

## License

BSD 3-Clause — see [LICENSE](LICENSE).
