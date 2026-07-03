# EnvVault

EnvVault is a lightweight local secret launcher for replacing long-lived values
with runtime-only `envvault://` references in project `.env` files or
`envvault exec --env` flags.

Links: [Documentation](https://trknhr.github.io/envvault/) |
[Homebrew tap](https://github.com/trknhr/homebrew-tap)

The default flow stores the real credential in the OS credential store and keeps
only a repository-safe reference in `.env`:

```dotenv
OPENAI_API_KEY=envvault://openai/dev
DATABASE_URL=envvault://database/dev
```

For APIs and SDKs that accept a custom endpoint, EnvVault also has an
experimental localhost proxy mode. The child process receives a local proxy URL
and local token instead of the real provider key:

```dotenv
OPENAI_BASE_URL=envvault://openai/dev/base-url
OPENAI_API_KEY=envvault://openai/dev/token
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
envvault proxy list
envvault exec --env OPENAI_API_KEY=envvault://openai/dev -- npm run dev
envvault exec --env-file .env -- npm start
```

`envvault admin start` starts the local browser UI for adding credentials and
creating optional proxies. The printed URL includes a per-run local admin token.
The UI does not display stored credential values.

The default flow intentionally passes the resolved credential to the child
process environment at launch. Use proxy mode only when an API client accepts a
custom base URL and you want to avoid passing the real provider key to the child
process.

## Security Limitations

EnvVault Local MVP reduces credential exposure; it does not create a sandbox.

- A child process can read any credential value or local proxy token placed in
  its environment until it exits.
- A process running as the same OS user can use the same OS credential store
  permissions as the user.
- If the OS credential store is compromised, stored provider credentials are
  compromised.
- EnvVault does not redact prompts, stdout, stderr, HTTP bodies, shell history,
  or application logs outside its own outputs.
- Direct `envvault://<credential>` references resolve to raw credential values.
  This is the default compatibility path for local development.
- Proxy mode can reduce provider-key exposure, but it requires the app or SDK to
  accept a custom base URL and bearer token.

## Status

This repository contains the local-first implementation path: strict reference
parsing, OS keyring abstraction, browser admin server, direct credential
resolution, optional provider proxies, process environment construction,
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
- [Proxies](docs/proxies.md)
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

- [Gemini SDK app example](examples/gemini-sdk-app/README.md)
- [Env app example](examples/env-app/README.md)
- [OpenAI-compatible proxy app example](examples/openai-proxy-app/README.md)
- [Gemini AI SDK proxy app example](examples/gemini-ai-sdk-proxy-app/README.md)

## Development

Run the standard verification set:

```bash
go test ./...
go vet ./...
go test -race ./...
```

No command should print raw provider keys, resolved credentials, Authorization
headers, or local proxy bearer tokens.
