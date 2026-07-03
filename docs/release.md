# Release Packaging

EnvVault releases are published by `.github/workflows/release.yml`. A `v*` tag
push builds the release archive matrix, uploads the GitHub Release assets, and
commits the generated Homebrew formula to `trknhr/homebrew-tap`.

The workflow needs a repository secret named `HOMEBREW_TAP_TOKEN`. Use a
fine-grained token that can write contents to `trknhr/homebrew-tap`.

## Publish From a Tag

Create or move the release tag to the commit being released, then push it:

```bash
git tag -f v0.1.0
git push -f origin v0.1.0
```

The release workflow:

1. Runs Go tests, static analysis, release acceptance checks, and secret scan.
2. Builds the VitePress documentation site.
3. Cross-builds and packages:
   - `darwin/amd64`
   - `darwin/arm64`
   - `linux/amd64`
   - `linux/arm64`
   - `windows/amd64`
4. Generates `SHA256SUMS`, Homebrew formula metadata, and Scoop metadata.
5. Creates or updates the GitHub Release for the tag.
6. Commits `Formula/envvault.rb` to the Homebrew tap.

Use the workflow dispatch form to rerun an existing tag. Disable `update_tap`
only when you want to rebuild/upload release assets without changing the tap.

## Local Packaging

## Build a Platform Binary

Build the end-user binary for the target platform:

```bash
GOOS=linux GOARCH=amd64 go build -trimpath -o build/envvault-linux-amd64 ./cmd/envvault
```

For Windows, use an `.exe` output path:

```bash
GOOS=windows GOARCH=amd64 go build -trimpath -o build/envvault-windows-amd64.exe ./cmd/envvault
```

## Package an Archive

Package the binary with README, required docs, and third-party notices:

```bash
go run ./cmd/envvault-release package \
  --version v0.1.0 \
  --platform linux/amd64 \
  --binary build/envvault-linux-amd64 \
  --dist dist
```

The command creates:

```text
dist/envvault_v0.1.0_linux_amd64.tar.gz
dist/SHA256SUMS
```

Windows targets produce `.zip` archives and include `envvault.exe`.

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
go run ./cmd/envvault-release package-manifests \
  --version v0.1.0 \
  --base-url https://github.com/trknhr/envvault/releases/download/v0.1.0 \
  --dist dist
```

The command creates:

```text
dist/homebrew/envvault.rb
dist/scoop/envvault.json
```

The generated files reference only archive URLs and checksums from `SHA256SUMS`. They are publish-ready inputs for a tap or bucket review, but the command does not publish them.

To prepare the Homebrew tap locally:

```bash
install -m 0644 dist/homebrew/envvault.rb \
  ../homebrew-tap/Formula/envvault.rb
```

The workflow handles the tap commit automatically. Use the local tap copy only
for manual recovery or formula review.

## Verification

Before publishing any release artifacts, run:

```bash
go test ./...
go vet ./...
go test -race ./...
go test ./test/acceptance -run TestRelease -count=1
go run ./cmd/envvault-ci secret-scan .
```

The same gate is defined in `.github/workflows/local-mvp.yml` for `ubuntu-latest`, `ubuntu-24.04`, `macos-latest`, and `macos-14`. Tier 1 platform validation still requires those workflow jobs to complete successfully on GitHub-hosted runners before release.
