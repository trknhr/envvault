# EnvVault

Keep real secrets out of project `.env` files and coding-agent prompts.

EnvVault replaces plaintext `.env` secrets with repository-safe `envvault://`
references. At runtime, it resolves credentials from the OS credential store or
starts a localhost proxy that gives the app a local URL and local proxy token.
An experimental Docker runtime can pass that temporary proxy capability into a
container without passing the upstream credential.
For existing agent-infra sandboxes, an experimental
[`sandbox exec` integration](/sandbox-exec) delegates execution and clipboard
handling to agent-infra while EnvVault manages temporary API access.

## Quick Start

Install EnvVault from the Homebrew tap:

```bash
brew install trknhr/tap/envvault
```

Register a credential once. Use the Admin UI for interactive setup:

```bash
envvault admin start
```

The printed localhost URL opens forms for adding credentials and creating
optional proxies. Stored credential values are not displayed by the UI.

For a shorter interactive CLI path, use `set`. It reads the value from a hidden
terminal prompt:

```bash
envvault credential set app/dev
```

For scripts or repeatable tests, use the same command with explicit stdin:

```bash
printf 'secret-value\n' | envvault credential set app/dev \
  --value-stdin
```

Remove an unused credential with `envvault credential delete app/dev`. If
profiles still reference it, deletion fails unless `--cascade` is supplied to
remove those dependent profiles too.

To find plaintext credentials that still need review, scan current local files:

```bash
envvault inspect --path .
```

The scan is read-only, includes ignored and untracked files, and never prints
credential values. Add `--include-medium` for contextual generic API-key
candidates and semantic `.env`, JSON, YAML, and TOML findings. Scanning uses
bounded parallel workers; `--depth 2` limits directory traversal and
`--workers 4` overrides automatic worker selection. Skipped paths are
summarized by count unless `--verbose` is supplied. Migration remains a
separate operation.

Use a repository-safe reference in the app's `.env` file or pass the same
reference with `envvault exec --env`:

```dotenv
APP_SECRET=envvault://app/dev
```

Launch the app through EnvVault:

```bash
envvault exec \
  --env APP_SECRET=envvault://app/dev \
  -- npm start

envvault exec --env-file .env -- npm start
```

For a tool that always reads a file under its home directory, inject a resolved
copy of a repository-safe JSON, YAML, or TOML source into an isolated temporary
home. For example, keep this non-secret file at `config/hogehoge.yaml`:

```yaml
token: envvault://app/dev
```

```bash
envvault exec \
  --home-file .hogehoge=config/hogehoge.yaml \
  -- your-command
```

The destination is relative to the isolated home. Relative source paths are
resolved from the invocation working directory, and absolute source paths are
also allowed.

## Credential Flows

- **Direct credential**: use `envvault://<credential>` for the default local
  development path. The child process receives the real value in its
  environment.
- **Isolated home file**: use repeatable
  `--home-file DEST=SOURCE` for a tool that requires a home-directory file.
  EnvVault resolves whole-string direct credential references in source values,
  leaves the source unchanged, and removes the isolated copy after the child
  exits normally. JSON, YAML, and TOML sources are supported.
- **Proxy**: use generated `envvault://<proxy>/base-url` and
  `envvault://<proxy>/token` references when an app accepts a custom endpoint
  and bearer token.
- **Docker sandbox**: reuse proxy output references with
  `envvault sandbox run`. The current prototype is `brokered`; direct container
  egress is not blocked.
- **Existing agent-infra sandbox**: launch a fresh process with
  [`envvault sandbox exec`](/sandbox-exec). API access is revoked when the
  session ends, but the container stays running. This requires a local,
  session-capable agent-infra build; stock 0.9.13 is unsupported.
- **URL-preserving outbound proxy**: attach a bearer provider profile with
  `--outbound-profile` when a supported proxy-aware sandbox client must keep the
  original provider URL. The upstream credential and ephemeral CA private key
  remain host-side.
- **Native agent auth**: explicitly use `--agent-auth native` to mount an
  EnvVault-managed, agent/profile-specific auth home. The official agent owns
  OAuth login and refresh; the sandbox can read the resulting credential state,
  so this path reports `materialized-static`.
- **External sandbox plugin**: let a trusted agent-sandbox control plane use
  `envvault sandbox plugin serve` to obtain sandbox-bound gateway leases without
  giving EnvVault responsibility for creating the sandbox.
- **Local state**: store only credential names and proxy policy in config; store
  real credential values in the OS credential store.

## Agent Skill

The public EnvVault skill is a small discovery stub. Detailed agent instructions
come from the installed CLI, keeping them aligned with its version.

Install the CLI and the cross-client discovery skill:

```bash
brew install trknhr/tap/envvault
envvault skills install
```

Or install the discovery stub from GitHub:

```bash
npx skills add trknhr/envvault --skill envvault -g -a codex
```

When activated, the stub runs `envvault skills get core` to load instructions
that match the installed binary. It installs the CLI only when the user
explicitly requests installation or setup; otherwise it asks first. See
[Agent Skill](/agent-skill) for scopes, upgrades, status, and uninstall.

## Advanced API Proxy

The [proxy examples](/examples) show the optional proxy workflow: a credential
stays in the OS credential store while the app receives only a localhost proxy
URL and local token.

See [Experimental Docker Sandbox](/sandbox) to run that proxy workflow inside a
container or attach an original-URL outbound profile. The
[daily Codex wrapper](/sandbox#daily-codex-wrapper-zsh) keeps agent OAuth and
per-session application profiles separate.

See [External Sandbox Sessions](/sandbox-exec) to launch a tool in an existing
agent-infra sandbox, or [External Sandbox Plugin](/sandbox-plugin) to build a
host-side controller around the connection protocol.
