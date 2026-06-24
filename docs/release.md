# Release Packaging

Credlease release packaging is local-only by default. The maintainer command builds an archive from an already-built `credlease` binary and writes `SHA256SUMS` in the chosen `dist` directory. It does not publish, deploy, upload, or push anything.

## Build a Platform Binary

Build the end-user binary for the target platform:

```bash
GOOS=linux GOARCH=amd64 go build -trimpath -o build/credlease-linux-amd64 ./cmd/credlease
```

For Windows, use an `.exe` output path:

```bash
GOOS=windows GOARCH=amd64 go build -trimpath -o build/credlease-windows-amd64.exe ./cmd/credlease
```

## Package an Archive

Package the binary with README, required docs, and third-party notices:

```bash
go run ./cmd/credlease-release package \
  --version v0.1.0 \
  --platform linux/amd64 \
  --binary build/credlease-linux-amd64 \
  --dist dist
```

The command creates:

```text
dist/credlease_v0.1.0_linux_amd64.tar.gz
dist/SHA256SUMS
```

Windows targets produce `.zip` archives and include `credlease.exe`.

## Release Matrix

The v0.1 release archive matrix is:

```text
darwin/amd64
darwin/arm64
linux/amd64
linux/arm64
windows/amd64
```

Run the packaging command once per platform binary. `SHA256SUMS` is updated incrementally; rerunning a platform replaces that archive's checksum entry while preserving other archive entries.

## Generate Package Manager Manifests

After all release archives are present in `SHA256SUMS`, generate local Homebrew and Scoop metadata:

```bash
go run ./cmd/credlease-release package-manifests \
  --version v0.1.0 \
  --base-url https://github.com/trknhr/credlease/releases/download/v0.1.0 \
  --dist dist
```

The command creates:

```text
dist/homebrew/credlease.rb
dist/scoop/credlease.json
```

The generated files reference only archive URLs and checksums from `SHA256SUMS`. They are publish-ready inputs for a tap or bucket review, but the command does not publish them.

## Verification

Before publishing any release artifacts, run:

```bash
go test ./...
go vet ./...
go test -race ./...
go test ./test/acceptance -run TestRelease -count=1
go run ./cmd/credlease-ci secret-scan .
```

The same gate is defined in `.github/workflows/local-mvp.yml` for `ubuntu-latest`, `ubuntu-24.04`, `macos-latest`, and `macos-14`. Tier 1 platform validation still requires those workflow jobs to complete successfully on GitHub-hosted runners before release.
