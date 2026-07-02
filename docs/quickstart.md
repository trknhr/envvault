# Quickstart

This page describes the EnvVault local workflow for API proxy references and
raw credential injection. The primary path is:

1. Store a real credential in the OS credential store.
2. Create a trusted local profile.
3. Paste the EnvVault-generated `.env` snippet into the app or pass the same
   references with `envvault exec --env`.
4. Launch the app through `envvault exec`.

## 1. Install EnvVault

After the v0.1.0 release assets are published, install from the Homebrew tap:

```bash
brew install trknhr/tap/envvault
```

## 2. Start the Local Admin UI

```bash
envvault admin start
```

Open the printed localhost URL. The URL contains a local admin token used by the
browser UI when it calls EnvVault APIs for that server run.

The UI can add credentials and create proxy or inject profiles. It does not
display stored credential values.

Use `envvault admin status` to check the background process and
`envvault admin stop` to stop it. `envvault admin serve` is available for
foreground debugging.

The CLI commands below are equivalent paths for scripting or repeatable local
testing.

## 3. Add a Provider Credential

Store the real provider key in the OS credential store:

```bash
printf 'sk-live-or-dev-key\n' | envvault credential add openai-key/dev \
  --value-stdin
```

You can also add the credential from the Admin UI.

## 4. Create an API Proxy Profile

Add a localhost proxy profile:

```bash
envvault proxy add openai/dev \
  --credential openai-key/dev \
  --provider generic \
  --target https://api.openai.com/v1 \
  --allow-path /chat/completions \
  --allow-path /responses \
  --allow-path /embeddings
```

The command prints a generic `.env` snippet:

```dotenv
ENVVAULT_PROXY_URL=envvault://openai/dev/base-url
ENVVAULT_PROXY_TOKEN=envvault://openai/dev/token
```

The Admin UI shows the same snippet with a copy button for proxy profiles.

## 5. Use the Snippet

Use the generated right-hand references with the variable names expected by the
app:

```dotenv
OPENAI_BASE_URL=envvault://openai/dev/base-url
OPENAI_API_KEY=envvault://openai/dev/token
```

`base-url` and `token` are EnvVault-generated proxy outputs. They are not
separate credentials to register.

You can keep those lines in `.env`, or skip creating a file and pass them
directly at launch:

```bash
envvault exec \
  --env OPENAI_BASE_URL=envvault://openai/dev/base-url \
  --env OPENAI_API_KEY=envvault://openai/dev/token \
  -- npm run dev
```

## 6. Run the App

```bash
envvault exec --env-file .env -- npm run dev
envvault exec --env-file .env -- npm start
```

`envvault exec` starts a localhost proxy, rewrites `OPENAI_BASE_URL` to that
proxy, and rewrites `OPENAI_API_KEY` to a local-only bearer token. The proxy
injects the real provider key only for requests matching the profile allowlist.

## 7. Use Raw Injection When Proxying Is Not Possible

Some SDKs and tools require a raw credential value and cannot be pointed at a
localhost proxy. For those cases, store the credential and create an inject
profile:

```bash
printf 'postgres://user:pass@127.0.0.1:5432/app\n' | envvault credential add database-url/dev \
  --value-stdin

envvault inject add database/dev \
  --credential database-url/dev \
  --project-binding none
```

Use a repository-safe reference:

```dotenv
DATABASE_URL=envvault://database/dev/value
```

This mode intentionally passes the raw credential to the child process
environment. Prefer a proxy profile when the target API or SDK supports it.

## 8. Inspect Health

```bash
envvault doctor
envvault credential list
envvault profile list
envvault doctor --repair
envvault reset --dry-run
```

`doctor` reports local state health. `doctor --repair` removes stale EnvVault
runtime locks and temporary files before re-checking health. `reset --dry-run`
shows EnvVault-owned files and keyring entries that would be removed.

## 9. Generate Shell Completion

```bash
envvault completion bash
envvault completion zsh
envvault completion fish
envvault completion powershell
```

Write the generated script to the completion location used by your shell.

## 10. Install The Agent Skill

EnvVault includes an agent skill for tools that need to launch commands with
EnvVault, configure proxy profiles, or debug `envvault://` references.

Install it from the public repository:

```bash
npx skills add trknhr/envvault --skill envvault
```

From a local checkout, use:

```bash
npx skills add . --skill envvault
```

Use the `skills` CLI options to choose global/project scope or a specific
agent, for example `-g` for global installation or `-a <agent>`.
Restart your agent after installing or updating skills.
