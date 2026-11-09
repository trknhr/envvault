# Host authentication profiles

Authentication profiles store JSON or YAML authentication documents encrypted
on the host. Sandboxes receive public `envvault://` references. The host proxy
extracts an access token only after checking the destination, method, path, and
reference. Refresh tokens and the complete document stay on the host.

This implementation is in the current checkout. Build it before trying the new
commands:

```sh
env -u GOROOT go build -o /tmp/envvault-dev ./cmd/envvault
```

The first stored authentication profile upgrades the configuration to version 2.
Use the updated binary for subsequent EnvVault commands; older releases reject
this configuration version. Existing version 1 configurations and opaque
credentials continue to work without conversion.

## Sign in once on the host

```sh
/tmp/envvault-dev auth login github --name github/work
/tmp/envvault-dev auth status github/work
```

Without `--client-id`, EnvVault runs the official host `gh` CLI with an isolated
temporary home and configuration directory. Complete its browser approval.
EnvVault encrypts the resulting access token and removes the temporary login
directory. Git's system configuration and credential helpers are isolated too;
the login selects gh's helper within the temporary directory, avoiding a second
Git credential write through macOS's `osxkeychain` helper. It does not use or
modify your normal host `gh` login. This fallback
stores the current token; it does not implement automatic refresh for gh-owned
authentication state. Sign in again if that token stops working.

For a GitHub app you control, enable device authorization and pass its public
client ID:

```sh
/tmp/envvault-dev auth login github --name github/work \
  --client-id YOUR_PUBLIC_CLIENT_ID --scope repo
```

When GitHub returns an expiry and refresh token, EnvVault refreshes on the host
before expiry and atomically saves the rotated token pair. Refresh is serialized
across processes. An app that returns only a non-expiring access token requires
no refresh. Failed refreshes require host sign-in; no refresh credential is sent
to the guest. OAuth requests use fixed GitHub endpoints and reject redirects.

## Import an existing document

```sh
/tmp/envvault-dev auth import service/work \
  --file "$HOME/private/service-auth.json" \
  --token-field /tokens/access_token
```

JSON pointers select nested fields. YAML is supported with `--format yaml`, or
by a `.yaml`/`.yml` extension. Standard input is available with `--file -`.
Documents are limited to 1 MiB; duplicate keys, YAML aliases, and multiple
documents are rejected. The selected token must be a nonempty HTTP header value.
The source file is retained. Do not put it in the mounted workspace.

Use `--expires-field /expires_at` for RFC3339 or Unix-second expiry. GitHub
refresh additionally needs `--provider github`, `--refresh-field /refresh_token`,
and the owning app's `--client-id`. A successful GitHub refresh normalizes the
stored document to GitHub's access-token, refresh-token, scope, and expiry fields.
Other providers currently support replacement on the host, without an automatic
refresh backend.

```sh
/tmp/envvault-dev auth list
/tmp/envvault-dev auth import service/work --file "$HOME/private/new-auth.json" \
  --token-field /tokens/access_token --overwrite
/tmp/envvault-dev auth logout service/work
```

Replacement takes effect on the next approved proxy request. Logout removes the
local encryption key and record, revoking broker access. It does not revoke the
upstream provider grant; use the provider's account settings for that.

## Attach destination rules

Authentication names share the credential reference namespace. Use them as a
proxy profile's `--credential`:

```sh
/tmp/envvault-dev proxy add github-api --credential github/work \
  --target https://api.github.com --allow-method GET --allow-path /user

/tmp/envvault-dev proxy add github-git --credential github/work \
  --git-repository trknhr/envvault
```

Profiles retain their normal workspace binding. Git repository rules allow
clone/fetch by default. Add `--git-write` when creating the rule to permit push.
The proxy checks both smart-HTTP endpoints and the advertised Git service.
Repository rules do not grant API access or access to other repositories. Git
SSH is outside this HTTPS bridge.

For the Microsandbox launcher, allow `github.com` and `api.github.com` in the
host policy's `https_hosts`, then launch:

```sh
./examples/microsandbox/agent shell
```

The launcher discovers authentication profiles and applicable saved destination
rules automatically. Inside the guest:

```sh
GH_TOKEN=envvault://github/work gh api user --jq .login
git clone https://github.com/trknhr/envvault.git /tmp/envvault-copy
```

The installed Git credential helper reads the public, read-only route catalog
and returns a reference. If several credentials cover the same repository, it
refuses to choose. The proxy replaces the reference with HTTPS Basic
authentication upstream. Neither Git nor gh receives the real token.

The existing host `credentials` policy can persist a `GH_TOKEN` reference in
the launch environment. Its method/path restrictions still apply. Network,
saved destination, rotation, and revocation changes apply live in Microsandbox;
process environment variables are chosen at launch.

For the core Docker adapter, attach saved rules with
`--outbound-profile github-api` (or workspace-authorized `--all`) and provide
`--env GH_TOKEN=envvault://github/work`. The Docker adapter remains cooperative
proxy delivery with direct container egress available. Its destination rules
are captured at launch; token rotation and auth-profile revocation are live.
The bundled Git helper is currently included in the Microsandbox image only.

## Storage and migration

Each document uses AES-256-GCM with its own random key in the OS credential
store. Encrypted records live under the EnvVault data directory's
`auth-profiles/`, with directory mode 0700 and file mode 0600. Public selectors
and identity metadata are authenticated with the ciphertext. The guest receives
only references, applicable routes, and a public proxy CA.

`envvault export` includes authentication documents inside the passphrase-
encrypted bundle. Import creates fresh local encryption keys and record IDs;
existing names require `--overwrite`. `doctor` checks local auth records, and
`reset` includes their keys and encrypted files.

Existing native logins in the persistent guest home are retained. After testing
the managed reference path, remove GitHub from `native_auth_hosts` to enforce
the managed path for GitHub requests. Remove an old guest login only as an
explicit migration step. Codex subscription authentication remains its existing
native login; this feature does not convert it to managed GitHub authentication.
