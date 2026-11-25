# Deploying claimward-server (v0.11.1)

Every secret is a **file in a credentials directory**, `$CREDENTIALS_DIRECTORY`,
never an environment variable. The names are fixed:

| File | Needed when |
|------|-------------|
| `wg-private-key` | always |
| `admin-token` | you want the admin API/WebUI (no file = disabled) |
| `goauthn-gateway-secret` | `AUTH_PROVIDER=go-authn` |
| `github-token` | any tenant has `members` |

The server refuses a file that is a symlink, not a regular file, readable by
group or other, not owned by its own uid, empty, or over 64 KiB. Each platform
below gives the files the right owner and mode. (Two root-owned shapes are
accepted: `0440` with the process's group, Kubernetes; and a read-only ACL for
the process's uid, systemd. CI starts the systemd unit to prove the second.)

`/metrics` is **off** unless `METRICS_ADDR` is set; the examples carry it as a
commented line.

| Platform | Directory | Files | Unit |
|----------|-----------|-------|------|
| systemd | set by `LoadCredentialEncrypted=` | with `DynamicUser=yes` (as shipped): root-owned with a read-only ACL for the service's uid, which the server accepts; with a fixed `User=` on a filesystem without ACLs: owned by the service user, `0400`. Private tmpfs | [`systemd/claimward-server.service`](systemd/claimward-server.service) |
| Docker Compose / Swarm | `/run/secrets` (set `CREDENTIALS_DIRECTORY` by hand) | Swarm: `mode: 0400`; plain Compose: chown/chmod the host file | [`compose/compose.yaml`](compose/compose.yaml) |
| Podman (Quadlet) | `/run/secrets` (set by hand) | `Secret=...,mode=0400,uid=...` | [`podman/claimward-server.container`](podman/claimward-server.container) |
| Kubernetes | the Secret volume's mount path (set by hand) | `defaultMode: 0440` + `fsGroup`: files are root:fsGroup `0440`, accepted; the pod runs as uid/gid 65532 with only `NET_ADMIN`, which needs `setcap cap_net_admin=+ep` on the image binary (see below) | [`kubernetes/claimward-server.yaml`](kubernetes/claimward-server.yaml) |
| OpenBSD (rc.d, pf) | `/etc/claimward/credentials` (the rc.d script sets `CREDENTIALS_DIRECTORY`) | owned by `_claimward`, `0400`, in a `0700` directory (`install(1)`) | [`openbsd/claimward_server`](openbsd/claimward_server) |
| s6 (no systemd) | `/run/sdcreds/claimward-server`, set by `sdcreds s6-run` | owned by the service user, `0400`, in a private tmpfs | [`s6/claimward-server/`](s6/claimward-server/run) |

The container image is `ghcr.io/claimward/claimward-vpn-server:<tag>`, built
from the [`Dockerfile`](../Dockerfile) on every tag for amd64 and arm64
(distroless, uid 65532). It is signed with cosign (keyless) and carries a build
provenance attestation:

```sh
cosign verify ghcr.io/claimward/claimward-vpn-server:v0.11.1 \
  --certificate-identity-regexp '^https://github.com/claimward/claimward-vpn-server/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The WireGuard interface (`wg0`) must already exist on the host (for
containers: host networking).

## systemd

```sh
# one credential at a time, encrypted to this host (TPM2 and/or the host key)
wg genkey | sudo systemd-creds encrypt --name=wg-private-key - /etc/credstore.encrypted/claimward.wg-private-key

# optional ones
printf '%s' "$TOKEN" | sudo systemd-creds encrypt --name=github-token - /etc/credstore.encrypted/claimward.github-token
printf '%s' "$TOKEN" | sudo systemd-creds encrypt --name=admin-token  - /etc/credstore.encrypted/claimward.admin-token
printf '%s' "$SECRET" | sudo systemd-creds encrypt --name=goauthn-gateway-secret - /etc/credstore.encrypted/claimward.goauthn-gateway-secret

sudo install -m 0644 systemd/claimward-server.service /etc/systemd/system/
# uncomment a LoadCredentialEncrypted= line for each optional credential you made
sudo systemctl daemon-reload && sudo systemctl enable --now claimward-server
```

`--name` must equal the credential name the unit gives (`name:path`), or
decryption fails. `systemd-analyze verify claimward-server.service` checks the
unit; `systemd-analyze security claimward-server.service` scores the hardening.

## Kubernetes (non-root)

Since v0.7.1 the pod runs as uid/gid 65532, `runAsNonRoot: true`, with
`capabilities: drop [ALL], add [NET_ADMIN]`, `allowPrivilegeEscalation: false`,
`readOnlyRootFilesystem: true` and the `RuntimeDefault` seccomp profile. The
Secret volume has `defaultMode: 0440` and the pod `fsGroup: 65532`, so the files
are `root:65532`, `0440`: the server accepts a root-owned `0440` file whose
group is its gid or a supplementary group. `0444`/`0644`, a foreign group or
another owner are refused.

**Does `NET_ADMIN` work for a non-root uid? Not by `add` alone.** The server
needs it for wgctrl, nftables and the interface MTU, and it never raises
capabilities itself. Kubernetes puts an added capability in the bounding and
permitted sets but sets no ambient capability, and on `execve` of a non-root
uid the kernel clears the permitted set unless the binary has file
capabilities. So the image's binary must carry them:

```sh
setcap cap_net_admin=+ep /claimward-server   # in the image build
```

The published image already does: the [`Dockerfile`](../Dockerfile) runs
`setcap` in the build stage and copies the binary into the distroless final
stage, and the CI lane `image` exports the FINAL image and reads
`security.capability` back (with a control extraction that must show none). A
self-built image must keep the attribute through any copy.

`no_new_privs` (`allowPrivilegeEscalation: false`) does not prevent this, since
the file capability grants nothing beyond what `add` already put in the
permitted set. This is the kernel's documented behaviour (capabilities(7)); it
was not run on a cluster here. Without the `setcap`, the first netlink call
fails with `EPERM`; the fallback is uid 0 with `defaultMode: 0400`.

## OpenBSD (7.9 and 8.0)

Files: [`openbsd/`](openbsd/): `claimward_server` (rc.d), `environment.example`,
`hostname.wg0.example`, `pf.conf.example`.

**Two processes (privilege separation, since v0.11.0).** wg(4) peer
configuration is behind `suser(9)` (`sys/net/if_wg.c`, `wg_ioctl_set`:
`if ((ret = suser(curproc)) != 0) return ret;`), and `/dev/pf` is guarded only
by its device node: `pfopen` in `sys/net/pf_ioctl.c` checks the minor number and
nothing else. OpenBSD has no capability or privileged-group mechanism that
would let an unprivileged user do either, so the rc.d script starts the daemon
as root, and the daemon splits in two:

- the **parent** (root) does the kernel's side and nothing else: it adds and
  removes WireGuard peers, sets the tunnel MTU and loads the pf anchor. It reads
  no credential, serves no network, and `unveil(2)`s only `/dev/pf`;
- the **child** (`_claimward`, started by the parent with no supplementary
  group) holds the secrets, the TLS and gRPC listeners, the identity provider
  and the tenant policy. Before it serves it `unveil(2)`s the TLS key and
  certificate, the tenants file and the few files DNS and TLS roots need, and
  `pledge(2)`s `stdio rpath inet dns`: no write, no exec, no other process. If
  it cannot drop privileges, unveil or pledge, the server does not start, and
  there is no flag to turn that off. There is no chroot: the child needs
  `/etc/resolv.conf` and the certificate roots, which `unveil` grants
  precisely.

The two talk over a socketpair with a small length-prefixed protocol of five
requests (add a peer: a key and an address inside `VPN_CIDR`; remove a peer
this run added; sweep the peers a previous run left, once, before any peer;
set the tunnel MTU, once, within 1280..9000; install the tenants' firewall,
which the parent compiles itself, so the child cannot name a rule or an
interface). The parent refuses everything else (malformed, oversized,
unknown, out of the pool) and ends the session after 16 refusals. What a
compromised child can still do is what the child is for: change the policy of
the peers in the pool. It cannot touch the host's other interfaces, rules or
files. When the child ends the parent removes the peers this run added, and
the other way round.

Because the child is not root, **the ports must be above 1024** (the defaults
8443 and 8444 are); to serve on 443, redirect it with a pf `rdr-to`.

```sh
# the server binary (from a release, or built with GOOS=openbsd)
install -m 0555 claimward-server /usr/local/bin/claimward-server

# the unprivileged account
useradd -g =uid -c claimward -d /var/empty -s /sbin/nologin -r 1..999 _claimward

# directories and secrets: owned by _claimward, files 0400. The environment
# file stays root's: rc.d reads it as root.
install -d -m 0755 -o root -g wheel /etc/claimward
install -d -m 0700 -o _claimward -g _claimward /etc/claimward/credentials
install -m 0400 -o _claimward -g _claimward /path/to/wg-private-key /etc/claimward/credentials/wg-private-key
# optional: admin-token, github-token, goauthn-gateway-secret (same install line)
# the TLS key and certificate and the tenants file: -o _claimward, 0400 / 0444

# non-secret settings, then edit
install -m 0600 -o root -g wheel openbsd/environment.example /etc/claimward/environment

# wg0 (same key as the credential; the file holds a secret): edit, then bring it up
install -m 0640 -o root -g wheel openbsd/hostname.wg0.example /etc/hostname.wg0
sh /etc/netstart wg0

# pf: add the lines of openbsd/pf.conf.example to /etc/pf.conf, then
pfctl -f /etc/pf.conf && pfctl -e

install -m 0555 openbsd/claimward_server /etc/rc.d/claimward_server
rcctl enable claimward_server
rcctl start claimward_server && rcctl check claimward_server
```

`rcctl start` reports `(ok)` only once the server accepts connections on
`LISTEN_ADDR` (the script's `rc_check` is the listener, not a `pgrep`), so a
daemon that exits first, for instance on a credential it does not own, is
`(failed)`.

The server logs to syslog (`daemon.info`, `/var/log/daemon`). It refuses to start
without `anchor "claimward"` in the main ruleset, with `set skip on` covering
`wg0`, and on any release but 7.9 and 8.0. The `openbsd` CI lane installs this
very script in real 7.9 and 8.0 VMs, runs `rcctl start`, checks the startup line
and `rcctl check`, asserts that the processes are a root parent and one
`_claimward` child and that the credential belongs to `_claimward`, enrolls a
device through the child and finds its peer on `wg0` (an unregistered key is
refused and never reaches `wg0`), runs `rcctl stop` (the peer is gone), starts
with a credential owned by root (it must fail), and then removes the anchor from
`pf.conf` and asserts that the start fails.

## Hosts without systemd

[`go-authn/sdcreds`](https://github.com/go-authn/sdcreds) (v0.2.0 or later)
provides the same directory under s6. The service directory is
[`s6/claimward-server`](s6/claimward-server/run) (`run`, `finish`). `sdcreds
s6-run` decrypts the files of `--source` into a private tmpfs (mode 0400, owned
by `--user`, which is the shape the server accepts: the process's own file),
sets `CREDENTIALS_DIRECTORY`, and starts the server as that user in a child
whose capability set is exactly what `--keep-cap` names. The server needs
`CAP_NET_ADMIN` and nothing else, so the example keeps that one; `no_new_privs`
stays on. `s6-run` needs root and `CAP_SYS_ADMIN` (it mounts).

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin claimward
sudo sdcreds setup                       # host secret, if missing
sudo install -d /etc/claimward/credentials.encrypted
wg genkey | sudo sdcreds encrypt --name=wg-private-key - /etc/claimward/credentials.encrypted/wg-private-key
# optional: github-token, admin-token, goauthn-gateway-secret, the same way
printf 'WG_ENDPOINT=vpn.example.org:51820\nAUTH_PROVIDER=github\nGITHUB_ALLOWED_ORGS=example-org\n' | sudo tee /etc/claimward/env
sudo cp -a s6/claimward-server /etc/s6-scan/   # your scan directory; s6-svscan picks it up
```

Rules to know: every file of `--source` must be named like its credential and
encrypted with that `--name` (an unknown name stops the start); `/etc/claimward/env`
is for non-secret settings only; `CAP_NET_ADMIN` acts on the network namespace the
supervision tree runs in, the host's unless you start `s6-svscan` inside one of
its own (`ip netns exec`). The CI lane `s6-sdcreds` starts this directory under a
real `s6-svscan` (the server drives a real wireguard link and nftables, in a
network namespace), checks the derived public key in the log, `CapEff` ==
`0x1000`, that no secret is in the environment, that a 0644 credential is
refused, and that stopping the service takes the mount away.

Containers do not need `sdcreds`: Compose, Podman and Kubernetes (above) mount
secrets as files already.

## Migrating from v0.5.0

`ADMIN_TOKEN`, `WG_PRIVATE_KEY`, `WG_PRIVATE_KEY_FILE` and
`GOAUTHN_GATEWAY_SECRET_FILE` are refused at start. Move each value into the file
named above and unset the variable. A tenant with `members` now needs
`github-token` (it authenticates `GET /users/{login}`; no scope is required).
