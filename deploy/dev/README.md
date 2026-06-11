# Local dev — Dex OIDC with YubiKey (WebAuthn) 2FA

A ready-to-run [Dex](https://dexidp.io) OIDC provider for developing Claimward,
configured with **YubiKey / FIDO2 WebAuthn as a second factor** after the
password login.

- **Issuer:** `http://localhost:5556/dex`
- **Client:** `claimward` (public; loopback redirect; PKCE)
- **Test user:** `user@claimward.test` / `claimward` — then a YubiKey
- **Second factor:** WebAuthn, external security key (`authenticatorAttachment: cross-platform`)

> **Why run Dex from source?** WebAuthn MFA is merged upstream
> ([dexidp/dex#4704](https://github.com/dexidp/dex/pull/4704)) but not in a
> released version yet. `pkgx dex` (2.45.1) does **not** have it, so we run Dex
> from `master`. MFA also requires `DEX_SESSIONS_ENABLED=true`.
>
> **Why `localhost`, not `127.0.0.1`?** A WebAuthn RP ID must be a domain;
> browsers reject IP addresses. `localhost` is both a valid RP ID and a secure
> context, so the issuer/origin use `localhost`.

## Run it

```sh
# from the repo root
task dex                      # go run dexidp/dex@master + DEX_SESSIONS_ENABLED=true
```

Then the control plane, wired to it (another shell):

```sh
task run:dev:oidc             # AUTH_PROVIDER=oidc, issuer=http://localhost:5556/dex
```

## Sign in (first time registers the key)

1. The client opens the browser to Dex; sign in as `user@claimward.test` /
   `claimward`.
2. **First login:** Dex prompts to **register** a security key — touch your
   YubiKey. The credential is stored against the user.
3. **Every login after:** Dex asks you to **tap the YubiKey** as the second
   factor before issuing the token.

CLI:

```sh
export CLAIMWARD_SERVER=http://127.0.0.1:8080
export CLAIMWARD_AUTH_PROVIDER=oidc
export CLAIMWARD_OIDC_ISSUER=http://localhost:5556/dex
export CLAIMWARD_OIDC_CLIENT_ID=claimward
claimward login
```

macOS app: `task config:init` (in claimward-vpn-app-osx) writes a matching
`config.json`.

## WebAuthn config

See the `mfa:` block in [`dex-config.yaml`](dex-config.yaml): a `WebAuthn`
authenticator scoped to the `local` connector, applied to all clients via
`defaultMFAChain`. Tune `userVerification` (require a PIN), `attestationPreference`,
or `authenticatorAttachment` (drop it to also allow Touch ID / platform keys).

## Notes

- In-memory storage → Dex state (incl. registered keys) resets on restart.
- Storage is in-memory, so a real deployment needs a persistent storage backend
  for the registered WebAuthn credentials.
