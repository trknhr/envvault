# Quickstart

This page describes the Local MVP workflow. Local archive packaging, local Homebrew/Scoop metadata generation, and CI gate definitions are available, while package-manager publication and green Tier 1 platform runs remain release blockers before a v0.1 release.

## 1. Initialize Credlease

```bash
credlease init
```

The Local MVP initialization flow creates private config, data, and cache directories, installs a pinned compatible Talos runtime, stores root secrets in the OS credential store, migrates SQLite, and exports a stable JWKS file.

Re-running `credlease init` must be idempotent and must not silently rotate or destroy existing secrets.

## 2. Add a Process Profile

```bash
credlease profile add process backend-a/dev \
  --resource https://api.dev.example.com \
  --scope repository:read \
  --scope issue:read \
  --ttl 10m \
  --max-ttl 30m
```

The default project binding mode is `git-remote-and-root`. First use requires interactive approval. Non-interactive approval fails closed.

## 3. Replace Long-Lived `.env` Values

Use a repository-safe reference:

```dotenv
BACKEND_A_TOKEN=credlease://backend-a/dev
```

Do not add query strings or fragments. Scope, resource, and TTL come from the local trusted profile, not from repository files.

## 4. Run a Child Process

```bash
credlease exec --env-file .env -- npm run dev
credlease exec --env-file .env -- codex
```

Credlease resolves whole-value references, derives short-lived JWTs, stops the managed Talos runtime before starting the child process, and then injects only the leased token into the child environment.

## 5. Export JWKS for a Local Backend

```bash
credlease jwks export --output ~/.config/backend-a/credlease-jwks.json
credlease issuer show
```

The backend should validate issuer, signature, expiry, resource, scope, and purpose.

This repository includes a runnable Go backend example:

```bash
go run ./examples/backend-go/cmd/backend \
  --jwks ~/.config/backend-a/credlease-jwks.json \
  --issuer "$(credlease issuer show)" \
  --resource http://127.0.0.1:8080 \
  --complete-url http://127.0.0.1:8080/auth/credlease/complete \
  --post-login-url http://127.0.0.1:8080/
```

Use `--secure-cookies` when serving the example over HTTPS.

## 6. Add a Browser Session Profile

```bash
credlease profile add browser-session admin-web/dev \
  --resource https://admin.dev.example.com \
  --exchange-url https://admin.dev.example.com/auth/credlease/browser-sessions \
  --complete-url https://admin.dev.example.com/auth/credlease/complete \
  --post-login-url https://admin.dev.example.com/ \
  --scope browser:session:create \
  --bootstrap-ttl 60s \
  --code-ttl 30s \
  --session-ttl 30m
```

## 7. Open a Browser Session

```bash
credlease open admin-web/dev
credlease open admin-web/dev --browser chrome
credlease open admin-web/dev --print-url
```

The bootstrap JWT is sent only in the exchange request Authorization header. The browser receives only a short-lived one-time code in the launch URL.

## 8. Inspect Health

```bash
credlease doctor
credlease doctor --repair
credlease reset --dry-run
```

`doctor` reports metadata-only status. `doctor --repair` stops recorded stale managed Talos processes and removes stale runtime locks and Credlease temporary files before re-checking health. `reset --dry-run` shows Credlease-owned files and keyring entries that would be removed.

## 9. Generate Shell Completion

```bash
credlease completion bash
credlease completion zsh
credlease completion fish
credlease completion powershell
```

Write the generated script to the completion location used by your shell. Completion output is static command metadata and does not read profiles, keyring entries, JWKS files, or runtime state.
