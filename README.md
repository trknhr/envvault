# EnvVault

EnvVault is a local-first credential launcher and localhost credential proxy for
replacing long-lived values with runtime-only local references in project
`.env` files or `envvault exec --env` flags.

Links: [Documentation](https://trknhr.github.io/envvault/) |
[Homebrew tap](https://github.com/trknhr/homebrew-tap)

API proxy references split the SDK base URL from the local bearer token:

```dotenv
OPENAI_BASE_URL=envvault://openai/dev/base-url
OPENAI_API_KEY=envvault://openai/dev/token
```

Raw credential injection is available for tools that cannot use a localhost
proxy:

```dotenv
DATABASE_URL=envvault://database/dev/value
```

## Install

Install EnvVault from the [Homebrew tap](https://github.com/trknhr/homebrew-tap):

```bash
brew install trknhr/tap/envvault
```

Common commands:

```bash
envvault admin start
envvault credential list
envvault profile list
envvault exec --env OPENAI_API_KEY=envvault://openai/dev/token -- npm run dev
envvault exec --env-file .env -- npm start
```

`envvault admin start` starts the local browser UI for adding credentials and
creating proxy or inject profiles. The printed URL includes a per-run local
admin token. The UI does not display stored credential values.

For API proxy profiles, `envvault exec` starts a localhost proxy, rewrites the
base URL to that proxy, and gives the child process a local-only token. The real
provider key stays in the OS credential store and is added only to outbound
requests that match the proxy profile's method and path allowlist.

## Security Limitations

EnvVault Local MVP reduces credential exposure; it does not create a sandbox.

- A child process can read any local proxy token or raw injected value placed in
  its environment until it exits.
- A process running as the same OS user can use the same OS credential store
  permissions as the user.
- If the OS credential store is compromised, stored provider credentials are
  compromised.
- EnvVault does not redact prompts, stdout, stderr, HTTP bodies, shell history,
  or application logs outside its own outputs.
- External API credentials are protected only when the app can be pointed at the
  EnvVault localhost proxy. If an SDK or tool insists on receiving the raw
  provider key directly, EnvVault cannot keep that key out of the child process
  environment.
- `envvault://<profile>/value` intentionally injects the raw credential into the
  child process environment. Use it only when proxying is not possible.

## Status

This repository contains the local-first implementation path: strict reference
parsing, profile policy, OS keyring abstraction, browser admin server, raw
inject profiles, provider proxy profiles, process environment construction,
metadata-only audit records, reset/doctor support, runnable examples, and
acceptance fixtures.

Local archive packaging is available through
`go run ./cmd/envvault-release package`, and local Homebrew/Scoop metadata can
be generated with `go run ./cmd/envvault-release package-manifests`.
`.github/workflows/local-mvp.yml` defines the test, vet, race, release, and
secret-scan gate for macOS and Ubuntu runners. `.github/workflows/release.yml`
publishes tagged release archives and updates the Homebrew tap.

## Documentation

- [Documentation site](https://trknhr.github.io/envvault/)
- [Quickstart](docs/quickstart.md)
- [Profiles](docs/profiles.md)
- [Threat model](docs/threat-model.md)
- [Uninstall](docs/uninstall.md)
- [Recovery](docs/recovery.md)
- [Third-party notices](docs/third-party-notices.md)

## Agent Skill

EnvVault includes an agent skill at [skills/envvault/SKILL.md](skills/envvault/SKILL.md).
Install it with the `skills` CLI:

```bash
npx skills add trknhr/envvault --skill envvault
```

From a local checkout, use:

```bash
npx skills add . --skill envvault
```

Check installed skills:

```bash
npx skills list
```

Use the `skills` CLI options to choose global/project scope or a specific
agent, for example `-g` for global installation or `-a <agent>`.
Restart your agent after installing or updating skills.

## Examples

- [OpenAI-compatible proxy app example](examples/openai-proxy-app/README.md)
- [Gemini SDK app example](examples/gemini-sdk-app/README.md)
- [Gemini AI SDK proxy app example](examples/gemini-ai-sdk-proxy-app/README.md)
- [Raw inject app example](examples/inject-app/README.md)

## Development

Run the standard verification set:

```bash
go test ./...
go vet ./...
go test -race ./...
```

No command should print raw provider keys, raw injected credentials,
Authorization headers, or local proxy bearer tokens.
