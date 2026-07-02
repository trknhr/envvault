# Release Gate

This page lists the local checks that must pass before a v0.1 release candidate
is treated as releasable.

Run the full gate:

```bash
go test ./...
go vet ./...
go test -race ./...
go test ./test/acceptance -run TestRelease -count=1
go run ./cmd/envvault-ci secret-scan .
```

The GitHub Actions workflow runs the same gate on the configured Ubuntu and
macOS Tier 1 runners. Package publication is separate and requires explicit
maintainer action.

## Coverage Focus

The v0.1 gate focuses on:

- Local credential storage through the OS credential store.
- Admin UI credential/profile creation.
- `envvault://.../base-url` and `envvault://.../token` proxy references.
- `envvault://.../value` raw inject references.
- Localhost proxy method and path allowlists.
- Child process environment construction through `envvault exec`.
- Secret redaction in EnvVault-owned outputs.
- Reset, doctor, release packaging, and secret scanning.

## Open Release Notes

- Package-manager publication is not part of the local release gate.
- Raw inject mode intentionally passes the credential to the child process; use
  proxy mode whenever the target API or SDK supports a custom base URL.
