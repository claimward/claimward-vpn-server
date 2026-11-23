# claimward-vpn-server


Control plane for the Claimward VPN. It authenticates devices against a
pluggable identity provider — **GitHub** by default, any **OIDC** issuer, or a
**go-authn** provider — and programs a **WireGuard** gateway, one peer per enrolled device.

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
| `GET /api/v1/tenants` | The tenants the caller may connect to (see [Tenants](#tenants)) |
| `GET /healthz` | Liveness |
| `GET /metrics` | Prometheus exposition |

## Flow

```
client --Bearer token + wg pubkey--> /enroll
  ├─ verifier.Verify    resolve identity: GitHub API (+ org allowlist), OIDC ID token, or go-authn access token
  ├─ registered         go-authn only: the key must be registered by the same subject (403 key_not_registered)
  ├─ chooseTenant       the requested tenant, or the caller's only one (409 tenant_required, 403 not_a_member)
  ├─ ipam.Allocate      next free address from VPN_CIDR (server takes .1)
  ├─ wg.AddPeer         wgctrl: add peer with AllowedIPs = clientIP/32
  └─ store.Put          remember the lease
client <-- assigned IP, server pubkey, endpoint, the tenant's routes + DNS, gRPC endpoint, keepalive, lease expiry --
```

A background reaper (every minute) removes peers whose lease expired (no heartbeat).

Leases and tenants are held **in memory**: a restart forgets every enrollment
and every tenant created through the admin API, leaving the `default` tenant
seeded from `PUSH_ROUTES` and `DNS`. At startup the server therefore **removes
the peers a previous run left** on the interface: those whose only allowed IP
is a `/32` inside `VPN_CIDR`, the shape it gives every peer. Any other peer
(configured by hand, a site-to-site link) is left alone. Kept, they would be
nobody's: never reaped, never checked against the provider's list, so a person
disabled before the restart would keep a working tunnel. Devices find
themselves unknown at their next lease renewal and enroll again (from
claimward-vpn-client v0.3.0).

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
- **Fail-closed:** a list past its expiry (its `exp`, set by the provider) admits nobody new, while
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
  and live updates. The stream is re-authorised before every push and every 15 s:
  it ends when the device is deregistered or reaped, when the person leaves the
  tenant, when the tenant is deleted, and at the token's expiry (the client
  reconnects with a fresh token).
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

## Access policy: what a peer may reach is enforced here

Pushing routes to a client is advice: a modified client can send anywhere.
So each tenant has a **policy**, and the gateway **enforces** it with nftables
(from Go, over netlink; nothing shells out to `nft`).

A policy is a list of allow rules, `{cidr, proto, ports}`, `proto` being `tcp` or
`udp` and `ports` numbers or `"lo-hi"` ranges. Mésocentre file access, where a
peer reaches only the file server on tcp/445 (SMB) and tcp+udp/88 (Kerberos):

```json
[
  {
    "id": "default",
    "policy": [
      {"cidr": "10.20.0.5/32", "proto": "tcp", "ports": [445, 88]},
      {"cidr": "10.20.0.5/32", "proto": "udp", "ports": [88]}
    ]
  }
]
```

Load it with `TENANTS_FILE=/etc/claimward/tenants.json` (a JSON array of
tenants, with the same fields as the admin API: `id`, `name`, `domains`,
`groups`, `idps`, `dns`, `policy`), or `POST`/`PUT` a tenant with a `policy`
to the admin API. A tenant file's `default` entry replaces `PUSH_ROUTES`.

- **One source of truth.** The `AllowedIPs` pushed to clients are the distinct
  destination CIDRs of the policy (`allowed_ips` is overwritten when a policy is
  set), so what a client is told and what the gateway lets through cannot drift.
- **Default deny** on traffic arriving on `WG_INTERFACE`: in the `forward` hook
  (to the networks behind the gateway) **and** the `input` hook (to the gateway
  host itself, which may be the file server). Only IPv4 is allowed; whatever a
  tenant's rules do not name is dropped. Traffic that does not arrive on the
  wg interface is never touched.
- **One table, `inet claimward`**, replaced atomically in a single netlink
  transaction at start and after every change of peers or tenants. A peer's
  `/32` is in the set of the tenant it enrolled into; a peer whose tenant is
  deleted is in no set and is dropped.
- **Fail closed.** At start, if the ruleset cannot be installed (not Linux, no
  `CAP_NET_ADMIN`, no nf_tables) the server does not start. An enrollment whose
  ruleset cannot be installed is refused and the peer removed. If a later
  update fails, deny-all is installed. The table is left in place when the
  process exits, so a dead gateway keeps denying. Use `WG_DRYRUN=true` for
  development: the ruleset is only logged.
- **Tenants without a policy** (the pre-0.3 `allowed_ips`/`PUSH_ROUTES` form)
  keep their meaning: every protocol and port to those CIDRs, now enforced.
  A tenant with neither reaches nothing.
- **DNS is not implicit.** A pushed DNS server is reachable only if the policy
  names it (udp and tcp `53`).
- The policy is parsed strictly (unknown fields, IPv6, `any`, empty ports and
  more than 1024 rules or 64 ports per rule are refused) and the parsers are
  fuzzed.

The Linux integration test (`internal/fw`, `TestNetnsPolicyIsEnforced`) builds
a peer, a gateway and a file server in network namespaces and checks every
allowed and denied flow. It needs root: it is skipped, with the reason printed,
elsewhere, and the privileged CI lane sets `CW_REQUIRE_NETNS=1` so that it can
not be skipped there.

## Configuration (environment)

| Var | Required | Default | Notes |
|-----|----------|---------|-------|
| `AUTH_PROVIDER` | | `github` | identity provider: `github`, `oidc` or `go-authn` |
| `GITHUB_ALLOWED_ORGS` | github | — | CSV org-membership allowlist. **REQUIRED with `AUTH_PROVIDER=github`**, with no opt-out: the server refuses to start without it, and the verifier refuses every token if it is empty (an empty list would admit any GitHub account) |
| `GITHUB_API_URL` | | `https://api.github.com` | set for GitHub Enterprise |
| `OIDC_ISSUER` | when `oidc` or `go-authn` | — | issuer URL (discovery) |
| `OIDC_CLIENT_ID` | when `oidc` or `go-authn` | — | expected token audience |
| `OIDC_ALLOWED_DOMAINS` | | — | CSV email-domain allowlist (oidc authz); only an address the IdP marks `email_verified` counts |
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
| `PUSH_ROUTES` | | `VPN_CIDR` | CSV AllowedIPs of the `default` tenant |
| `TENANTS_FILE` | | — | JSON file of tenants and their access policies (see *Access policy*) |
| `DNS` | | — | CSV DNS servers of the `default` tenant |
| `KEEPALIVE` | | `25` | persistent keepalive (seconds) |
| `LEASE_TTL` | | `24h` | lease duration without heartbeat |
| `MAX_DEVICES_PER_SUBJECT` | | `5` | most devices one account may have enrolled at once (a further new key gets 429 `too_many_devices`) |
| `LISTEN_ADDR` | | `:8443` | HTTP control-plane listen address |
| `GRPC_ADDR` | | `:8444` | RouteService gRPC listen address |
| `GRPC_ENDPOINT` | | — | `host:port` advertised to clients for route streaming |
| `ADMIN_TOKEN` | | — | bearer for the admin API/WebUI; empty disables admin |
| `DEBUG` | | — | any value enables debug logging |
| `TLS_CERT` / `TLS_KEY` | | — | enable HTTPS **and TLS on the gRPC RouteService**. A route watch carries the bearer token, and claimward clients refuse a plaintext one except on loopback; without these, devices connect but get no live route updates |

## Run locally (no WireGuard device needed)

The server is assembled and started from `cmd/claimward-server` (see
`Taskfile.yml` — `task run`, or `task run:dev` for a dry run on `:8080` with an
ephemeral key, `task dex` + `task run:dev:oidc` against a local Dex, see
[`deploy/dev`](deploy/dev/README.md)). With `WG_DRYRUN=true` no real WireGuard device
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
