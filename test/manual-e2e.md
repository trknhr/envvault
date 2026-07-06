# Manual E2E Playbook

This playbook installs EnvVault from a local release archive and exercises the
v0.1.1 local credential flows by hand.

## Safety Notes

EnvVault stores long-lived values in the OS credential store. Changing `HOME`
isolates config, data, and cache paths, but it does not fully isolate the OS
credential store for the current OS user. Use a disposable OS user or a machine
where deleting EnvVault-owned keychain entries is acceptable before running the
cleanup commands.

Do not run `git push`, publish artifacts, or deploy from this playbook.

## 1. Build, Package, and Install Locally

Run from the repository root:

```bash
export EV_ROOT="$(pwd)"
export EV_VERSION="v0.1.1"
export EV_GOOS="$(go env GOOS)"
export EV_GOARCH="$(go env GOARCH)"
export EV_WORK="$EV_ROOT/tmp/manual-e2e"
export EV_BUILD="$EV_WORK/build"
export EV_DIST="$EV_WORK/dist"
export EV_INSTALL="$EV_WORK/install"
export EV_PACKAGE_DIR="envvault_${EV_VERSION}_${EV_GOOS}_${EV_GOARCH}"

rm -rf "$EV_WORK"
mkdir -p "$EV_BUILD" "$EV_DIST" "$EV_INSTALL"

go build -trimpath -o "$EV_BUILD/envvault" ./cmd/envvault

go run ./cmd/envvault-release package \
  --version "$EV_VERSION" \
  --platform "$EV_GOOS/$EV_GOARCH" \
  --binary "$EV_BUILD/envvault" \
  --dist "$EV_DIST"

case "$EV_GOOS" in
  windows)
    unzip "$EV_DIST/${EV_PACKAGE_DIR}.zip" -d "$EV_INSTALL"
    ;;
  *)
    tar -xzf "$EV_DIST/${EV_PACKAGE_DIR}.tar.gz" -C "$EV_INSTALL"
    ;;
esac

export PATH="$EV_INSTALL/$EV_PACKAGE_DIR:$PATH"
hash -r

command -v envvault
envvault completion bash >/dev/null
```

Expected result: `command -v envvault` prints the installed binary path under
`tmp/manual-e2e/install`.

## 2. Use Disposable Local Paths

```bash
export HOME="$EV_WORK/home"
mkdir -p "$HOME"
```

On macOS this redirects EnvVault config/data/cache under the temporary home
directory, but keychain entries are still per OS user.

## 3. Smoke Test the Admin Server

```bash
envvault admin start
envvault admin status

ADMIN_URL="$(envvault admin status | sed -E 's/^running pid=[0-9]+ url=//')"
curl -fsS "$ADMIN_URL" | grep 'EnvVault'

envvault admin stop
envvault admin status
```

Expected result:

- `admin start` prints a localhost URL with a token.
- `admin status` prints `running ...` while the server is up.
- The `curl` command finds `EnvVault` in the HTML.
- The final `admin status` prints `stopped`.

If `127.0.0.1:17890` is in use, start on another fixed port:

```bash
envvault admin start --addr 127.0.0.1:17891
```

## 4. Direct Credential Flow

This checks the default path for tools that require a normal environment value.

```bash
printf 'postgres://user:pass@127.0.0.1:5432/app\n' | envvault credential add database/dev \
  --value-stdin

envvault exec --env DATABASE_URL=envvault://database/dev -- \
  "$EV_ROOT/examples/env-app/app.sh"
```

Expected result:

```text
DATABASE_URL loaded for app
```

## 5. API Proxy Flow

Start the mock OpenAI-compatible provider:

```bash
go run ./examples/openai-proxy-app/mock-provider.go > "$EV_WORK/mock-provider.log" 2>&1 &
EV_MOCK_PROVIDER_PID=$!
sleep 1
```

Register a credential and proxy:

```bash
printf 'sk-local-demo\n' | envvault credential add openai-key/dev \
  --value-stdin

envvault proxy add openai-proxy/dev \
  --credential openai-key/dev \
  --provider generic \
  --target http://127.0.0.1:18080/v1 \
  --allow-path /chat/completions \
  --allow-method POST \
  --project-binding none

envvault exec \
  --env OPENAI_BASE_URL=envvault://openai-proxy/dev/base-url \
  --env OPENAI_API_KEY=envvault://openai-proxy/dev/token \
  -- \
  "$EV_ROOT/examples/openai-proxy-app/app.sh"
```

Expected result: the JSON response contains `pong`.

Stop the mock provider when finished:

```bash
kill "$EV_MOCK_PROVIDER_PID"
wait "$EV_MOCK_PROVIDER_PID" 2>/dev/null || true
```

## 6. Inspect and Cleanup

Preview local state deletion:

```bash
envvault reset --dry-run
```

If you are using a disposable OS user or are comfortable deleting EnvVault-owned
OS credential store entries for this user:

```bash
envvault admin stop || true
envvault reset --yes
rm -rf "$EV_WORK"
```

If you already had real EnvVault state in this OS user, do not run
`envvault reset --yes`; remove only the temporary files under `tmp/manual-e2e`
and manually review OS credential store entries before deleting anything.
