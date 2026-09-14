# Codex Sandbox for EnvVault Development

This image extends the minimal Codex example with the Go toolchain and native
build tools needed to develop EnvVault. The default Go version matches
`go.mod`, while Node.js remains available for building the documentation.

Build the image from the repository root:

```bash
docker build \
  --tag envvault-codex-go:local \
  examples/codex-sandbox-go
```

Then start Codex from the EnvVault repository:

```bash
envvault sandbox run -it \
  --runtime docker \
  --image envvault-codex-go:local \
  -- codex
```

Useful checks inside the sandbox include:

```bash
go test ./...
go vet ./...
npm ci
npm run docs:build
```

The sandbox's ephemeral home is intentionally small. This image therefore
stores Go and npm caches in `.envvault-cache/` inside the mounted workspace;
the repository ignores that directory. Docker integration tests still require
a separate trusted environment with access to a Docker daemon.

When deliberately upgrading a toolchain, override the pinned defaults with
Docker build arguments and update the repository configuration in the same
change:

```bash
docker build \
  --build-arg GO_VERSION=1.25.0 \
  --build-arg NODE_VERSION=22.22.2 \
  --build-arg CODEX_VERSION=0.147.0 \
  --tag envvault-codex-go:local \
  examples/codex-sandbox-go
```
