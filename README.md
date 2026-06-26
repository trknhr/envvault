# EnvVault

EnvVault is a local-first credential launcher and localhost credential proxy for replacing long-lived values in project `.env` files with runtime-only credentials.

Repository-safe references for first-party leased tokens look like this:

```dotenv
BACKEND_A_TOKEN=envvault://backend-a/dev
```

Third-party API proxy references split the SDK base URL from the local bearer token:

```dotenv
OPENAI_BASE_URL=envvault://openai/dev/base-url
OPENAI_API_KEY=envvault://openai/dev/token
```

Raw credential injection is available for tools that cannot use a localhost proxy:

```dotenv
DATABASE_URL=envvault://database/dev/value
```

Target Local MVP commands:

```bash
envvault admin start
envvault exec --env-file .env -- codex
envvault exec --env-file .env -- npm run dev
envvault open admin-web/dev
```

`envvault admin start` starts the local browser UI for adding credentials and
creating proxy or inject profiles. The printed URL includes a per-run local
admin token. The UI does not display stored credential values.

For third-party APIs, `envvault exec` starts a localhost proxy, rewrites the
base URL to that proxy, and gives the child process a local-only token. The real
provider key stays in the OS credential store and is added only to outbound
requests that match the proxy profile's method and path allowlist.

## Security Limitations

EnvVault Local MVP reduces credential exposure; it does not create a sandbox.

- A child process can read any leased token placed in its environment until it exits or the token expires.
- A process running as the same OS user can still invoke `envvault token` unless additional OS controls are used.
- If the OS credential store is compromised, the local trust root is compromised.
- Local issuer public keys are not automatically trusted by remote services. Remote backends need explicit key registration or a future centralized STS.
- EnvVault does not redact prompts, stdout, stderr, HTTP bodies, shell history, or application logs outside its own outputs.
- Third-party credentials are protected only when the app can be pointed at the EnvVault localhost proxy. If an SDK or tool insists on receiving the raw provider key directly, EnvVault cannot keep that key out of the child process environment.
- `envvault://<profile>/value` intentionally injects the raw credential into the child process environment. Use it only when proxying is not possible.

## Local MVP Status

This repository contains the Local MVP implementation path: strict reference parsing, profile policy, OS keyring abstraction, browser admin server, raw inject profiles, third-party provider proxy profiles, managed Talos runtime installation and lifecycle for first-party leased tokens, local issuer boundaries, process environment construction, browser-session helpers, verifier packages, metadata-only audit records, reset/doctor support, runnable examples, and acceptance fixtures.

Local archive packaging is available through `go run ./cmd/envvault-release package`, and local Homebrew/Scoop metadata can be generated with `go run ./cmd/envvault-release package-manifests`. `.github/workflows/local-mvp.yml` defines the test, vet, race, release, and secret-scan gate for macOS and Ubuntu runners. Package-manager publication and green Tier 1 platform runs are still required before a v0.1 release.

## Documentation

- [Quickstart](docs/quickstart.md)
- [Manual E2E playbook](docs/manual-e2e.md)
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
- [OpenAI-compatible proxy app example](examples/openai-proxy-app/README.md)
- [Gemini SDK app example](examples/gemini-sdk-app/README.md)
- [Raw inject app example](examples/inject-app/README.md)
- [Local MVP app example](examples/local-mvp-app/README.md)

## Development

Run the standard verification set:

```bash
go test ./...
go vet ./...
go test -race ./...
```

No command should print raw parent keys, signing keys, Authorization headers, browser login codes, or issued JWTs except the intentional `envvault token` credential-helper output path.
