# Quickstart

This page describes the Local MVP workflow for first-party leased JWTs, browser sessions, and third-party API proxying. Local archive packaging, local Homebrew/Scoop metadata generation, and CI gate definitions are available, while package-manager publication and green Tier 1 platform runs remain release blockers before a v0.1 release.

## 1. Initialize EnvVault

```bash
envvault init
```

The Local MVP initialization flow creates private config, data, and cache directories, installs a pinned compatible Talos runtime, stores root secrets in the OS credential store, migrates SQLite, and exports a stable JWKS file.

Re-running `envvault init` must be idempotent and must not silently rotate or destroy existing secrets.

## 2. Start the Local Admin UI

```bash
envvault admin start
```

Open the printed localhost URL. The URL contains a local admin token used by the
browser UI when it calls EnvVault APIs for that server run. The UI can add
credentials and create proxy or inject profiles, but it does not display stored
credential values.

Use `envvault admin status` to check the background process and
`envvault admin stop` to stop it. `envvault admin serve` is available for
foreground debugging.

The CLI commands below are equivalent fallback paths for scripting or testing.

## 3. Add a Process Profile

```bash
envvault profile add process backend-a/dev \
  --resource https://api.dev.example.com \
  --scope repository:read \
  --scope issue:read \
  --ttl 10m \
  --max-ttl 30m
```

The default project binding mode is `git-remote-and-root`. First use requires interactive approval. Non-interactive approval fails closed.

## 4. Replace Long-Lived `.env` Values

Use a repository-safe reference:

```dotenv
BACKEND_A_TOKEN=envvault://backend-a/dev
```

Do not add query strings or fragments. Scope, resource, and TTL come from the local trusted profile, not from repository files.

## 5. Run a Child Process

```bash
envvault exec --env-file .env -- npm run dev
envvault exec --env-file .env -- codex
```

EnvVault resolves whole-value references, derives short-lived JWTs, stops the managed Talos runtime before starting the child process, and then injects only the leased token into the child environment.

## 6. Use a Third-Party API Proxy

Store the real provider key in the OS credential store:

```bash
printf 'sk-live-or-dev-key\n' | envvault credential add openai-key/dev \
  --value-stdin
```

Add a localhost proxy profile:

```bash
envvault proxy add openai/dev \
  --credential openai-key/dev \
  --provider generic \
  --target https://api.openai.com/v1 \
  --allow-path /chat/completions \
  --allow-path /responses \
  --allow-path /embeddings
```

Use repository-safe references in `.env`:

```dotenv
OPENAI_BASE_URL=envvault://openai/dev/base-url
OPENAI_API_KEY=envvault://openai/dev/token
```

`envvault exec` starts a localhost proxy, rewrites `OPENAI_BASE_URL` to that
proxy, and rewrites `OPENAI_API_KEY` to a local-only bearer token. The proxy
injects the real provider key only for requests matching the profile allowlist.

## 7. Use Raw Injection When Proxying Is Not Possible

Some SDKs and tools require a raw credential value and cannot be pointed at a
localhost proxy. For those cases, store the credential and create an inject
profile:

```bash
printf 'postgres://user:pass@127.0.0.1:5432/app\n' | envvault credential add database-url/dev \
  --value-stdin

envvault inject add database/dev \
  --credential database-url/dev \
  --project-binding none
```

Use a repository-safe reference:

```dotenv
DATABASE_URL=envvault://database/dev/value
```

This mode intentionally passes the raw credential to the child process
environment. Prefer a proxy profile when the target API or SDK supports it.

## 8. Export JWKS for a Local Backend

```bash
envvault jwks export --output ~/.config/backend-a/envvault-jwks.json
envvault issuer show
```

The backend should validate issuer, signature, expiry, resource, scope, and purpose.

This repository includes a runnable Go backend example:

```bash
go run ./examples/backend-go/cmd/backend \
  --jwks ~/.config/backend-a/envvault-jwks.json \
  --issuer "$(envvault issuer show)" \
  --resource http://127.0.0.1:8080 \
  --complete-url http://127.0.0.1:8080/auth/envvault/complete \
  --post-login-url http://127.0.0.1:8080/
```

Use `--secure-cookies` when serving the example over HTTPS.

## 9. Add a Browser Session Profile

```bash
envvault profile add browser-session admin-web/dev \
  --resource https://admin.dev.example.com \
  --exchange-url https://admin.dev.example.com/auth/envvault/browser-sessions \
  --complete-url https://admin.dev.example.com/auth/envvault/complete \
  --post-login-url https://admin.dev.example.com/ \
  --scope browser:session:create \
  --bootstrap-ttl 60s \
  --code-ttl 30s \
  --session-ttl 30m
```

## 10. Open a Browser Session

```bash
envvault open admin-web/dev
envvault open admin-web/dev --browser chrome
envvault open admin-web/dev --print-url
```

The bootstrap JWT is sent only in the exchange request Authorization header. The browser receives only a short-lived one-time code in the launch URL.

## 11. Inspect Health

```bash
envvault doctor
envvault doctor --repair
envvault reset --dry-run
```

`doctor` reports metadata-only status. `doctor --repair` stops recorded stale managed Talos processes and removes stale runtime locks and EnvVault temporary files before re-checking health. `reset --dry-run` shows EnvVault-owned files and keyring entries that would be removed.

## 12. Generate Shell Completion

```bash
envvault completion bash
envvault completion zsh
envvault completion fish
envvault completion powershell
```

Write the generated script to the completion location used by your shell. Completion output is static command metadata and does not read profiles, keyring entries, JWKS files, or runtime state.
