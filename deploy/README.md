# Deploying claimward-server (v0.10.0)

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

The container image is `ghcr.io/claimward/claimward-vpn-server:<tag>`, built
from the [`Dockerfile`](../Dockerfile) on every tag for amd64 and arm64
(distroless, uid 65532). It is signed with cosign (keyless) and carries a build
provenance attestation:

```sh
cosign verify ghcr.io/claimward/claimward-vpn-server:v0.10.0 \
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

## Hosts without systemd

`go-authn/sdcreds` (`sdcreds s6-run`) will provide the same directory under s6
and similar supervisors, once its v0.1.0 is tagged. It is not tagged yet, and
nothing here depends on it: until then, create the directory by hand
(`install -d -m 0700`, files `0400`, owned by the service's uid) and export
`CREDENTIALS_DIRECTORY`.

## Migrating from v0.5.0

`ADMIN_TOKEN`, `WG_PRIVATE_KEY`, `WG_PRIVATE_KEY_FILE` and
`GOAUTHN_GATEWAY_SECRET_FILE` are refused at start. Move each value into the file
named above and unset the variable. A tenant with `members` now needs
`github-token` (it authenticates `GET /users/{login}`; no scope is required).
