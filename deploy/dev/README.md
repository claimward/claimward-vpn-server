# Local dev — Dex OIDC

A ready-to-run [Dex](https://dexidp.io) OIDC provider for developing Claimward
without an external identity provider.

- **Issuer:** `http://127.0.0.1:5556/dex`
- **Client:** `claimward` (public client; loopback redirect, PKCE)
- **Test user:** `user@claimward.test` / `claimward`

## Run it (via pkgx)

```sh
# from the repo root
task dex                      # = pkgx dex serve deploy/dev/dex-config.yaml
# …or directly:
pkgx dex serve deploy/dev/dex-config.yaml
```

Then run the control plane wired to it (in another shell):

```sh
task run:dev:oidc             # AUTH_PROVIDER=oidc, issuer=…/dex, dry-run on :8080
```

## Point a client at it

CLI:

```sh
export CLAIMWARD_SERVER=http://127.0.0.1:8080
export CLAIMWARD_AUTH_PROVIDER=oidc
export CLAIMWARD_OIDC_ISSUER=http://127.0.0.1:5556/dex
export CLAIMWARD_OIDC_CLIENT_ID=claimward
claimward login               # browser → sign in as user@claimward.test / claimward
```

macOS app: `task config:init` (in claimward-vpn-app-osx) writes a `config.json`
already pointing here.

## Notes

- Storage is in-memory — Dex state resets on restart (fine for dev).
- The client is `public: true`, so Dex accepts the native flow's loopback
  redirect (`http://127.0.0.1:<random>/callback`) on any port.
- Add real users by replacing the static password with a connector (LDAP,
  Google, GitHub, …) in `dex-config.yaml`.
