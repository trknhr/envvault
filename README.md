# EnvVault

Keep real secrets out of project `.env` files and coding-agent prompts.

EnvVault replaces plaintext `.env` secrets with repository-safe `envvault://`
references. At runtime, it resolves credentials from the OS credential store or
starts a localhost proxy that gives the app a local URL and local proxy token.
For tools that require a credential file under the user's home directory, it
can instead create an isolated temporary home containing only the requested
resolved files.

Links: [Documentation](https://trknhr.github.io/envvault/) |
[Homebrew tap](https://github.com/trknhr/homebrew-tap)

The default compatibility path stores the real credential in the OS credential
store and keeps only a repository-safe direct reference in `.env`:

```dotenv
APP_SECRET=envvault://app/dev
DATABASE_URL=envvault://database/dev
```

For APIs and SDKs that accept a custom endpoint, EnvVault also has an
experimental localhost proxy mode. The child process receives a local proxy URL
and local token instead of the real upstream credential:

```dotenv
APP_BASE_URL=envvault://api-proxy/dev/base-url
APP_API_TOKEN=envvault://api-proxy/dev/token
```

Public reference forms are intentionally small:

- `envvault://<credential>` resolves a direct credential.
- `envvault://<proxy>/base-url` and `envvault://<proxy>/token` resolve generated
  proxy outputs.

## Install

Install EnvVault from the [Homebrew tap](https://github.com/trknhr/homebrew-tap):

```bash
brew install trknhr/tap/envvault
```

Common commands:

```bash
envvault admin start
envvault credential set app/dev
envvault credential delete app/dev
envvault credential list
envvault inspect --path .
envvault proxy list
envvault exec --env APP_SECRET=envvault://app/dev -- npm run dev
envvault exec --env-file .env -- npm start
envvault exec --home-file .hogehoge=config/hogehoge.yaml -- your-command
```

`envvault credential set <name>` prompts for a credential with terminal echo
disabled, so no `printf` pipeline or secret-valued command-line argument is
needed. For non-interactive scripts, add `--value-stdin` to the same command.

`envvault credential delete <name>` removes the credential from the OS
credential store and local metadata. It refuses to delete credentials used by a
profile; pass `--cascade` only when the dependent profiles should be deleted
too.

`envvault admin start` starts the local browser UI for adding credentials and
creating optional proxies. The printed URL includes a per-run local admin token.
The UI does not display stored credential values.

The default flow intentionally passes the resolved credential to the child
process environment at launch. Use proxy mode only when an API client accepts a
custom base URL and you want to avoid passing the real upstream credential to
the child process.

`--home-file DEST=SOURCE` supports tools that always read a file such as
`~/.hogehoge`. `DEST` is a safe relative path inside a private, otherwise empty
temporary home. A relative `SOURCE` is resolved from the invocation working
directory; an absolute source path is also allowed. For example, a
repository-safe YAML source can contain normal configuration plus a direct
credential reference:

```yaml
endpoint: https://api.example.com
token: envvault://app/dev
```

Source filenames select JSON (`.json`), YAML (`.yaml` or `.yml`), or TOML
(`.toml`); extensionless names and single dotfiles default to JSON. EnvVault
recursively resolves only whole-string `envvault://<credential>` values, never
keys, and writes the result at `DEST`. A bare `--home-file .hogehoge` uses
`./.hogehoge` as both source and destination. The source is never modified, and
child changes are discarded. YAML mapping keys must be strings; anchors,
aliases, and merge keys are not supported. The option is repeatable.
`DEST=envvault://<credential>` remains available for tools whose entire file is
one raw credential.

## Inspect Local Files

Find potential raw credentials before moving them into the OS credential store:

```bash
envvault inspect --path .
envvault inspect --path ~/.config --depth 2 --include-medium
envvault inspect --path . --format json --fail-on-findings
```

`inspect` is read-only. It scans current files without reading Git history and
includes ignored and untracked files. It does not follow symlinks or print
credential values. High-confidence provider-specific Gitleaks and known-file
findings are shown by default; `--include-medium` also reports Gitleaks'
contextual generic API-key candidates and secret-named fields in `.env`, JSON,
YAML, and TOML files. Findings are candidates for review, not proof that a
value is valid. File inspection runs concurrently using an automatically
bounded worker count; use `--workers` to override it. `--depth 1` scans files
at the requested root and one nested directory, while the default `--depth 0`
is unlimited. The default output reports only the skipped-path count; add
`--verbose` to list every skipped path. Migration and source-file deletion are
intentionally separate steps.

## Security Limitations

EnvVault reduces credential exposure; it does not create a sandbox.

- A child process can read any credential value or local proxy token placed in
  its environment until it exits.
- A child process can read any credential file created with `--home-file`.
  EnvVault removes the isolated home when the child exits normally. A forced
  termination or system failure can leave it behind until
  `envvault doctor --repair` removes the stale workspace.
- Home-file isolation is environment based, not a filesystem sandbox. The child
  must honor `HOME` or the platform config-directory variables; a tool that
  resolves the OS account home independently can still reach the real home.
- The isolated home belongs to the foreground child lifetime. A daemonized
  descendant does not keep it alive after the direct child exits.
- A process running as the same OS user can use the same OS credential store
  permissions as the user.
- If the OS credential store is compromised, stored credentials are compromised.
- EnvVault does not redact prompts, stdout, stderr, HTTP bodies, shell history,
  or application logs outside its own outputs.
- Direct `envvault://<credential>` references resolve to raw credential values.
  This is the default compatibility path for local development.
- Proxy mode can reduce raw-secret exposure, but it requires the app or SDK to
  accept a custom base URL and bearer token.

## Status

This repository contains the local-first implementation path: strict reference
parsing, OS keyring abstraction, browser admin server, direct credential
resolution, isolated home-file injection, optional provider proxies, process
environment construction, read-only raw-credential inspection, metadata-only
audit records, reset/doctor support, runnable examples, and acceptance fixtures.

Local archive packaging is available through
`go run ./cmd/envvault-release package`, and local Homebrew/Scoop metadata can
be generated with `go run ./cmd/envvault-release package-manifests`.
`.github/workflows/ci.yml` defines the test, vet, race, release, and
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

No command should print raw secrets, resolved credentials, Authorization
headers, or local proxy bearer tokens.
