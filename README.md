# claimward-vpn-server


Control plane for the Claimward VPN. It authenticates devices against a
pluggable identity provider — **GitHub** by default, or any **OIDC** issuer —
and programs a **WireGuard** gateway, one peer per enrolled device.

Designed to run co-located on the Linux gateway host: it manages *peers* on an
existing `wg0` interface via `wgctrl` (the interface itself is created by
wg-quick/systemd at boot).

## Endpoints

Enrollment requests carry the user's bearer credential as
`Authorization: Bearer <token>` — a **GitHub OAuth access token** (default
provider), an **OIDC ID token** (`AUTH_PROVIDER=oidc`), or a go-authn
**access token** (`AUTH_PROVIDER=go-authn`, see [With go-authn](#with-go-authn)). Request/response
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

A key belongs to whoever enrolled it: enrolling a key another identity holds
is refused (`409 key_taken`). A WireGuard public key is public, and before
this an enrollment under another identity took the key over, and with it the
power to deregister its owner's device.

## With go-authn

With `AUTH_PROVIDER=go-authn`, [go-authn/bridge](https://github.com/go-authn/bridge)
is the identity provider: an OpenID Connect provider in front of a SAML
federation (RENATER, eduGAIN), which also keeps **whose each WireGuard key
is**. A valid token is no longer enough to enroll:

1. the client logs in once at the provider (device flow, scope
   `openid wireguard`) and registers its device's **public** key there
   (`POST /wireguard/key`). The private key never leaves the device;
2. it refreshes for `scope=openid`, which gives an access token addressed to
   this server (`OIDC_CLIENT_ID`), and calls `/api/v1/enroll` with it;
3. the server enrolls the key only if the provider's list has it **registered
   by the same subject**. Otherwise it answers `403 key_not_registered`. A
   lease never outlives the key's registration.

The list comes from [go-authn/wireguard](https://github.com/go-authn/wireguard):
- **Fetched with the gateway's own credentials**, signed by the provider for
  this gateway alone.
- **Refetched every `GOAUTHN_PEER_LIST_INTERVAL`.** A key the provider takes
  back (the person or their institution disabled, or the device removed) is
  dropped from `wg0` at the next fetch, and its heartbeat is refused.
- **Never older than one already seen**, which is the replay protection.
- **Fail-closed:** a list past its five minutes admits nobody new, while
  tunnels already up end with their leases.
- **Required at startup:** the first list is fetched before the server
  listens.
- **Refetched at once on a disabling,** with `GOAUTHN_SSF=true`: the gateway
  also polls the provider's Shared Signals stream (SSF 1.0, RFC 8936), reusing
  one stream rather than one per start. An event is a **trigger, never a
  decision**: it makes the list be read sooner, and the signed list alone says
  what may connect. A forged event therefore buys one extra fetch and nothing
  else, which is why events are not verified.

Only **access tokens** (`typ: at+jwt`, RFC 9068 §4) addressed to this server
are accepted, never an ID token. Tenants are matched on the token's `groups`
and `idp` (see [Tenants](#tenants)), and on an email domain only when the
provider verified the address.

## Other surfaces

Beyond the enrollment API, the server exposes:

- **RouteService (gRPC)** — a `Watch` stream (on `GRPC_ADDR`, default `:8444`;
  advertised to clients as `GRPC_ENDPOINT`) that pushes a client's tenant routes
  and live updates.
- **Admin API + WebUI** — a token-guarded (`ADMIN_TOKEN`) surface under `/admin/`:
  a `GET /admin/api/overview`, tenant CRUD at `/admin/api/tenants[...]`, and an
  embedded Svelte single-page app. Disabled unless `ADMIN_TOKEN` is set.
- **Prometheus metrics** — exposition at `/metrics`.

## Tenants

Routes are tenant-scoped, and **a person may belong to several tenants**. They
choose one per session, and the device connects to that one. A person belongs
to every tenant that names any of:

| | matched against |
|---|---|
| `domains` | the domain of a **verified** email (an unverified one is a string the person typed) |
| `groups` | the token's `groups` claim (OIDC; go-authn: eduPerson entitlements), or the person's GitHub organisations |
| `idps` | the institution that vouched for them: go-authn's `idp`, a SAML entity ID |

A person who matches none belongs to the `default` tenant, and only then.

| | |
|---|---|
| `GET /api/v1/tenants` | the tenants the caller may connect to, `[{id, name}]`, for a client to offer the choice |
| `POST /api/v1/enroll` with `tenant` | must be one of them (`403 not_a_member`); without one, the caller's only tenant. A person in several gets `409 tenant_required` with the list, rather than being routed into a network they did not choose |
| `POST /api/v1/heartbeat` | refused (`403 not_a_member`) once the person is no longer in the session's tenant |
| RouteService `Watch` | streams the routes of the tenant **the device enrolled into**, found by its key, which must be the caller's |

The admin API and WebUI edit the three membership lists beside the routes.

## Configuration (environment)

| Var | Required | Default | Notes |
|-----|----------|---------|-------|
| `AUTH_PROVIDER` | | `github` | identity provider: `github`, `oidc` or `go-authn` |
| `GITHUB_ALLOWED_ORGS` | | — | CSV org-membership allowlist (github authz; recommended) |
| `GITHUB_API_URL` | | `https://api.github.com` | set for GitHub Enterprise |
| `OIDC_ISSUER` | when `oidc` | — | issuer URL (discovery) |
| `OIDC_CLIENT_ID` | when `oidc` | — | expected token audience |
| `OIDC_ALLOWED_DOMAINS` | | — | CSV email-domain allowlist (oidc authz) |
| `GOAUTHN_GATEWAY_CLIENT_ID` | when `go-authn` | — | this gateway's own client at the go-authn provider (`wireguard_peers`) |
| `GOAUTHN_GATEWAY_SECRET_FILE` | when `go-authn` | — | its secret, **from a file only** |
| `GOAUTHN_PEER_LIST_INTERVAL` | | `30s` | how often the list of registered keys is fetched |
| `GOAUTHN_SSF` | | `false` | also listen to the provider's Shared Signals (poll), so a disabling is acted on at once; the gateway's client must be an SSF receiver there |
| `GOAUTHN_SSF_INTERVAL` | | `5s` | how often the SSF stream is polled |
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
| `TLS_CERT` / `TLS_KEY` | | — | enable HTTPS **and TLS on the gRPC RouteService**. A route watch carries the bearer token, and claimward clients refuse a plaintext one except on loopback; without these, devices connect but get no live route updates |

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
