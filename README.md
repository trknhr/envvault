# Credlease

Credlease is a local-first credential launcher for replacing long-lived values in project `.env` files with short-lived, scoped credentials issued at runtime.

Repository-safe references look like this:

```dotenv
BACKEND_A_TOKEN=credlease://backend-a/dev
```

Target Local MVP commands:

```bash
credlease exec --env-file .env -- codex
credlease exec --env-file .env -- npm run dev
credlease open admin-web/dev
```

## Security Limitations

Credlease Local MVP reduces credential exposure; it does not create a sandbox.

- A child process can read any leased token placed in its environment until it exits or the token expires.
- A process running as the same OS user can still invoke `credlease token` unless additional OS controls are used.
- If the OS credential store is compromised, the local trust root is compromised.
- Local issuer public keys are not automatically trusted by remote services. Remote backends need explicit key registration or a future centralized STS.
- Credlease does not redact prompts, stdout, stderr, HTTP bodies, shell history, or application logs outside its own outputs.
- GitHub PATs, Stripe secrets, and other third-party credentials that only support long-lived bearer secrets are not made safe by renaming them as Credlease references.

## Local MVP Status

This repository contains the Local MVP implementation path: strict reference parsing, profile policy, OS keyring abstraction, managed Talos runtime installation and lifecycle, local issuer boundaries, process environment construction, browser-session helpers, verifier packages, metadata-only audit records, reset/doctor support, a runnable Go backend example, and acceptance fixtures.

Local archive packaging is available through `go run ./cmd/credlease-release package`, and local Homebrew/Scoop metadata can be generated with `go run ./cmd/credlease-release package-manifests`. `.github/workflows/local-mvp.yml` defines the test, vet, race, release, and secret-scan gate for macOS and Ubuntu runners. Package-manager publication and green Tier 1 platform runs are still required before a v0.1 release.

## Documentation

- [Quickstart](docs/quickstart.md)
- [Profiles](docs/profiles.md)
- [Browser session protocol](docs/browser-session.md)
- [Threat model](docs/threat-model.md)
- [Uninstall](docs/uninstall.md)
- [Recovery](docs/recovery.md)
- [Release packaging](docs/release.md)
- [Release gate](docs/release-gate.md)
- [Remote STS notes](docs/remote-sts.md)
- [Implementation spec](docs/implementation-spec.md)
- [Third-party notices](docs/third-party-notices.md)

## Examples

- [Go backend example](examples/backend-go)
- [TypeScript backend example](examples/backend-typescript/README.md)
- [Browser session Go example](examples/browser-session-go/README.md)
- [Codex example](examples/codex/README.md)

## Development

Run the standard verification set:

```bash
go test ./...
go vet ./...
go test -race ./...
```

No command should print raw parent keys, signing keys, Authorization headers, browser login codes, or issued JWTs except the intentional `credlease token` credential-helper output path.
