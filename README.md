# claimward-vpn-server


Control plane for the Claimward VPN. It authenticates devices against a
pluggable identity provider — **GitHub** by default, any **OIDC** issuer, or a
**go-authn** provider — and programs a **WireGuard** gateway, one peer per enrolled device.

Designed to run co-located on the gateway host, Linux (nftables) or, from
v0.10.0, OpenBSD (pf, see [OpenBSD](#openbsd-pf-from-v0100)): it manages *peers* on an
existing `wg0` interface via `wgctrl` (the interface itself is created by
wg-quick/systemd at boot). On OpenBSD the `wgctrl` driver can read a device
but not configure it, so the gateway writes peers itself with the `SIOCSWG`
ioctl (as `ifconfig(8)` does), from v0.11.0: enrolment works there, with the pf
policy, the MTU and the privilege separation.

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
| `GET /metrics` | Prometheus exposition — on the separate `METRICS_ADDR` listener, not this port |

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
seeded from `PUSH_ROUTES` and `DNS` (it names nobody until a `TENANTS_FILE`
gives it `domains`, `groups`, `idps` or `members`). At startup the server therefore **removes
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
- **Admin API + WebUI** — a token-guarded (`admin-token` credential) surface under `/admin/`:
  a `GET /admin/api/overview`, tenant CRUD at `/admin/api/tenants[...]`, and an
  embedded Svelte single-page app. Disabled unless the `admin-token` credential exists.
- **Prometheus metrics** — exposition at `/metrics` on its own listener,
  `METRICS_ADDR` (off unless set: no default port), never on the enrollment port.
  Every listener has read, write and idle timeouts and a connection cap;
  the gRPC server enforces keepalive and a per-connection stream limit.

## Tenants

Routes are tenant-scoped, and **a person may belong to several tenants**. They
choose one per session, and the device connects to that one. A person belongs
to every tenant that names any of:

| | matched against |
|---|---|
| `domains` | the domain of a **verified** email (an unverified one is a string the person typed) |
| `groups` | the token's `groups` claim (OIDC; go-authn: eduPerson entitlements), or the person's GitHub organisations |
| `idps` | the institution that vouched for them: go-authn's `idp`, a SAML entity ID |
| `members` | GitHub **logins**, named one by one (see below) |

⛔ **A person who matches no tenant is refused**: `403 not_a_member` on
`/api/v1/tenants` and `/api/v1/enroll`, and `Watch` is refused. There is no
fallback tenant (before v0.5.0 such a person landed in `default`). The `default`
tenant receives only those its own `domains`, `groups`, `idps` or `members`
name, like any other. An unknown tenant ID is an error for the routes and the
watch, not the `default` tenant's routes.

### Named members, pinned to the account ID

`members` lists GitHub logins, which are readable but can be renamed and then
registered by somebody else. So the server **pins** each login to the account's
numeric ID: when a tenant is loaded (`TENANTS_FILE`) or created/updated through
the admin API, it asks `GET {GITHUB_API_URL}/users/{login}` (10 s timeout, 64 KiB
answer cap, `type` must be `User`) and stores the pair. Membership is matched on
the token's subject, `github:<id>`, never on the login: a renamed account whose
old login now belongs to another person is refused. An unresolvable login is an
error (the server does not start; the admin API answers `400`). The admin API
and WebUI show the logins (and `pinned`, read-only); to follow a rename, edit
the tenant again. Resolution is authenticated with the **`github-token`
credential** (a bearer, 5000 requests an hour; no scope is needed for public
data), which is **required as soon as any tenant has `members`**: without it the
server does not start, and the admin API answers `400`. The token is only sent
over https (or to a loopback address).

The organisation check does **not** use this token: it runs with the *person's*
own token, so a private membership is visible only if their token carries
`read:org`. `github-token` therefore stays optional when only organisations are
used.

A named member is also **admitted** by the GitHub entry gate without belonging
to an allowed organisation.

| | |
|---|---|
| `GET /api/v1/tenants` | the tenants the caller may connect to, `[{id, name}]`, for a client to offer the choice |
| `POST /api/v1/enroll` with `tenant` | must be one of them (`403 not_a_member`); without one, the caller's only tenant. A person in several gets `409 tenant_required` with the list, rather than being routed into a network they did not choose |
| `POST /api/v1/heartbeat` | refused (`403 not_a_member`) once the person is no longer in the session's tenant |
| RouteService `Watch` | streams the routes of the tenant **the device enrolled into**, found by its key, which must be the caller's |

The admin API and WebUI edit the four membership lists beside the routes.

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
    "members": ["octocat"],
    "policy": [
      {"cidr": "10.20.0.5/32", "proto": "tcp", "ports": [445, 88]},
      {"cidr": "10.20.0.5/32", "proto": "udp", "ports": [88]}
    ]
  }
]
```

Load it with `TENANTS_FILE=/etc/claimward/tenants.json` (a JSON array of
tenants, with the same fields as the admin API: `id`, `name`, `domains`,
`groups`, `idps`, `members`, `dns`, `policy`), or `POST`/`PUT` a tenant with a `policy`
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

### OpenBSD (pf), from v0.10.0

On OpenBSD the same policy is enforced with pf, programmed directly through the
`/dev/pf` ioctls (`internal/pf`); `pfctl` is never run and there is no fallback
to it. The behaviour is the same as on Linux: default deny on `WG_INTERFACE`,
IPv4 only (IPv6 across the tunnel is dropped), MSS clamping for both families,
fail closed.

- **Supported releases: 7.9 and 8.0** (they share one `struct pf_rule` layout).
  Any other release, and a layout that does not match the release's own
  `<net/pfvar.h>`, makes the server refuse to start.
- **You own `pf.conf`.** The server never edits the main ruleset: add
  `anchor "claimward"` to `/etc/pf.conf` and keep pf enabled. The policy is
  loaded into that anchor, in one pf transaction, and read back.
- **Refusals at start:** not root (`/dev/pf` is opened read-write), pf disabled,
  the main ruleset does not call `anchor "claimward"` (the policy would filter
  nothing), `set skip on` covering the WireGuard interface (`wg0`, `wg*`).
- **Deployment.** [`deploy/openbsd/`](deploy/openbsd/) ships an `rc.d` script,
  a `pf.conf` fragment, a `hostname.wg0` and the credentials layout
  ([deploy/README.md](deploy/README.md#openbsd-79-and-80)).
- **Privilege separation, from v0.11.0.** wg(4) peer configuration needs
  `suser(9)` and `/dev/pf` is root-only, so the daemon is two processes. The
  **parent** (root) only adds and removes WireGuard peers, sets the tunnel MTU
  and loads the pf anchor; it reads no credential, serves no network, and
  `unveil(2)`s `/dev/pf` alone. The **child**, run as `_claimward`, holds the
  secrets, the listeners and the policy, is restricted with `unveil(2)` and
  `pledge(2)` (`stdio rpath inet dns`) before it serves, and asks the parent
  over a socketpair. The parent refuses a malformed, oversized, unknown or
  out-of-pool request, and builds the ruleset itself, so the child never names a
  rule. If the child cannot drop privileges, unveil or pledge, the server does
  not start, and there is no flag to disable it. A compromised child can still
  change the policy of the peers in the pool; it cannot reach the rest of the
  host. Linux and `WG_DRYRUN` stay one process. Ports must be above 1024.
- **WireGuard peers, from v0.11.0.** wgctrl's OpenBSD driver can read a device
  but ConfigureDevice returns "driver is read-only", so `internal/wg` writes
  peers with `SIOCSWG` and `struct wg_data_io` (`<net/if_wg.h>`, as
  `ifconfig(8)` does), in the root parent: add a peer with its `/32`, replace
  its address, remove it. The kernel never reads `wgd_size`, so the encoder
  bounds every count (at most 8 peers and 16 addresses per call, IPv4 only)
  before the ioctl. The structure layout is generated from the release's own
  header (`internal/wg/abigen`, compared on 7.9 and 8.0 by the `pf ABI` lane) and
  checked against a C compiler; the `openbsd` lane adds, replaces, removes and
  sweeps peers on a real `wg(4)`, and enrols a device through the rc.d service.
  Before v0.11.0 every OpenBSD enrolment ended in a gateway error.
- **Table names** carry a per-load generation suffix, so the short window between
  the table commit and the rule commit never applies one tenant's rules to
  another tenant's peers.
- **The privileged parent has no `pledge(2)`.** The `pf` promise allows twelve
  `DIOC*` ioctls (`sys/kern/kern_pledge.c`, `pledge_ioctl`); it also needs
  `DIOCRINADEFINE`, `DIOCXROLLBACK`, `DIOCGETRULES`, `DIOCGETRULE`, `DIOCXEND`
  and `DIOCRGETADDRS`, and a pledge cannot be widened later. Its narrowing is
  that it is small, secret-free and network-free, and `unveil`ed.
- **Tests.** The `openbsd` CI lane runs `internal/pf` as root in real 7.9 and 8.0
  VMs: struct layout against the release's own header, load and read-back,
  `pfctl` as an oracle for the encoding, and a packet proof (traffic across
  pair(4) interfaces and routing domains is dropped or passed as the policy
  says, and the SYN's MSS option is read with `tcpdump`: measured 1460 without the
  clamp, 1350 with it, on a 1390 MTU, on 7.9 and 8.0).

## Credentials (v0.6.0)

**Every secret is a file in a credentials directory, never an environment
variable** (an environment is copied into every child process and every crash
dump). The directory is `$CREDENTIALS_DIRECTORY`: systemd sets it for
`LoadCredential=`/`LoadCredentialEncrypted=`; set it yourself for Docker/Podman
(`/run/secrets`) and Kubernetes (the Secret volume's mount path). The file
names are fixed, and one trailing newline is trimmed:

| File | Required | Content |
|------|----------|---------|
| `wg-private-key` | always | base64 WireGuard server key |
| `admin-token` | no | bearer of the admin API/WebUI; **without the file the admin API is disabled** |
| `goauthn-gateway-secret` | `AUTH_PROVIDER=go-authn` | the gateway client's secret |
| `github-token` | when any tenant has `members` | bearer for `GET /users/{login}` (see *Named members*) |

A missing required file stops the start and names the file. Before reading,
each file is checked through its open descriptor (`O_NOFOLLOW`, then `fstat`):
it must be a regular file (no symlink), owned by the server's uid, with no
group or other permission (`0400`), non-empty and at most 64 KiB. One more
shape is accepted, for Kubernetes: a file **owned by root, mode exactly `0440`,
whose group is the process's gid or one of its supplementary groups** (what a
Secret volume gives with `defaultMode: 0440` and `fsGroup`), so the pod need not
run as root. A third shape is what systemd gives a service run as another user
(`DynamicUser=yes`, `LoadCredential=`, `LoadCredentialEncrypted=`): a **root-owned
file whose access ACL names exactly one user, the server's uid, with read only**
(`user::r--`, `user:<uid>:r--`, `group::---`, `mask::r--`, `other::---`; `stat`
shows `0440` because the group bits are the ACL mask). The ACL is read from the
open descriptor; any other named user or group, any write or execute bit, or a
malformed or oversized ACL is refused. Otherwise the server refuses, with the fix: Swarm `mode: 0400`,
Kubernetes `defaultMode: 0440` + `fsGroup`/`runAsUser`/`runAsGroup`, Podman
`--secret ...,mode=0400`, else `chmod 0400`.

**Kubernetes and `NET_ADMIN` as a non-root uid.** `capabilities.add:
[NET_ADMIN]` alone is not enough: Kubernetes sets no ambient capability, the
server does not raise one, and the kernel drops the permitted set when a
non-root uid executes a binary without file capabilities. The image's binary
needs `setcap cap_net_admin=+ep` (see
[`deploy/kubernetes/`](deploy/kubernetes/claimward-server.yaml)); without it the
first netlink call fails with `EPERM`. This follows capabilities(7) and was not
measured on a cluster.

⛔ **Migration from v0.5.0** (breaking). `ADMIN_TOKEN`, `WG_PRIVATE_KEY`,
`WG_PRIVATE_KEY_FILE` and `GOAUTHN_GATEWAY_SECRET_FILE` are **no longer read**,
and the server refuses to start while any is set (no fallback). Put each value
in the file named above, unset the variable, and set `CREDENTIALS_DIRECTORY`.
Tenants with `members` now also need `github-token`. Ready-made units are in
[`deploy/`](deploy/README.md) (systemd, Compose, Podman Quadlet, Kubernetes,
s6). Hosts without systemd get the same directory from `go-authn/sdcreds`
(`sdcreds s6-run --keep-cap=CAP_NET_ADMIN`, v0.2.0): the files are 0400 and
owned by the service user, which the server accepts. See
[`deploy/s6/`](deploy/s6/claimward-server/run); CI starts it under a real
`s6-svscan` and checks `CapEff == 0x1000`. This server does not depend on it.

## Configuration (environment)

| Var | Required | Default | Notes |
|-----|----------|---------|-------|
| `AUTH_PROVIDER` | | `github` | identity provider: `github`, `oidc` or `go-authn` |
| `GITHUB_ALLOWED_ORGS` | github | — | CSV org-membership allowlist. With `AUTH_PROVIDER=github` it is **optional only when at least one tenant has `members`**; with neither the server refuses to start, with no opt-out, and the verifier refuses every token (an empty gate would admit any GitHub account). A GitHub identity is admitted if it is in an allowed org OR is a named member of a tenant |
| `GITHUB_API_URL` | | `https://api.github.com` | set for GitHub Enterprise |
| `OIDC_ISSUER` | when `oidc` or `go-authn` | — | issuer URL (discovery) |
| `OIDC_CLIENT_ID` | when `oidc` or `go-authn` | — | expected token audience |
| `OIDC_ALLOWED_DOMAINS` | | — | CSV email-domain allowlist (oidc authz); only an address the IdP marks `email_verified` counts |
| `GOAUTHN_GATEWAY_CLIENT_ID` | when `go-authn` | — | this gateway's own client at the go-authn provider (`wireguard_peers`) |
| `GOAUTHN_PEER_LIST_INTERVAL` | | `30s` | how often the list of registered keys is fetched |
| `GOAUTHN_SSF` | | `false` | also listen to the provider's Shared Signals (poll), so a disabling is acted on at once; the gateway's client must be an SSF receiver there |
| `GOAUTHN_SSF_INTERVAL` | | `5s` | how often the SSF stream is polled |
| `WG_ENDPOINT` | ✅ | — | public `host:port` advertised to clients |
| `CREDENTIALS_DIRECTORY` | ✅ | — | directory of the secret files (see *Credentials*) |
| `WG_INTERFACE` | | `wg0` | kernel interface to manage |
| `WG_DRYRUN` | | `false` | log peer ops instead of applying — local dev |
| `VPN_CIDR` | | `10.80.0.0/24` | address pool; `.1` is the gateway |
| `PUSH_ROUTES` | | `VPN_CIDR` | CSV AllowedIPs of the `default` tenant |
| `TENANTS_FILE` | | — | JSON file of tenants and their access policies (see *Access policy*) |
| `DNS` | | — | CSV DNS servers of the `default` tenant |
| `KEEPALIVE` | | `25` | persistent keepalive (seconds) |
| `LEASE_TTL` | | `24h` | lease duration without heartbeat |
| `TUNNEL_MTU` | | derived | MTU of the gateway's WireGuard interface, set by the server at start and advertised to clients as `mtu` in the enroll response. Unset: the uplink's MTU minus 80, capped at 1420 and floored at 1280 (1420 when the uplink cannot be read). Set: a whole number from 1280 to 9000, anything else stops the start. Clients lower it further to fit their own path. The same table `inet claimward` also clamps the MSS of every TCP SYN crossing the interface (forward both ways, and input for the gateway host itself) to this MTU minus 40 (IPv4) or 60 (IPv6), so a connection never announces a segment the tunnel cannot carry. Needs `CAP_NET_ADMIN` (the gateway already holds it); not applied under `WG_DRYRUN` |
| `MAX_DEVICES_PER_SUBJECT` | | `5` | most devices one account may have enrolled at once (a further new key gets 429 `too_many_devices`) |
| `LISTEN_ADDR` | | `:8443` | HTTP control-plane listen address |
| `GRPC_ADDR` | | `:8444` | RouteService gRPC listen address |
| `METRICS_ADDR` | | off | where `/metrics` is served, on its own listener. Unset means no metrics at all (there is no default port to clash with another service, `:9090` being Prometheus' own); set it to `127.0.0.1:9100`, say. It names every tenant: expose it only on a trusted network |
| `GRPC_ENDPOINT` | | — | `host:port` advertised to clients for route streaming |
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
export CREDENTIALS_DIRECTORY=$HOME/.local/state/claimward-dev-creds
(umask 077; mkdir -p "$CREDENTIALS_DIRECTORY"; wg genkey > "$CREDENTIALS_DIRECTORY/wg-private-key")
chmod 0400 "$CREDENTIALS_DIRECTORY/wg-private-key"
export WG_DRYRUN=true LISTEN_ADDR=:8080

go run ./cmd/claimward-server
```

## License

BSD 3-Clause — see [LICENSE](LICENSE).
