# Quickstart

This page describes the default EnvVault local workflow:

1. Store a real credential in the OS credential store.
2. Create a trusted local inject profile.
3. Keep only an `envvault://.../value` reference in `.env`.
4. Launch the app through `envvault exec`.

Use API proxy profiles as an advanced option when an SDK accepts a custom base
URL and bearer token.

## 1. Install EnvVault

Install from the Homebrew tap:

```bash
brew install trknhr/tap/envvault
```

## 2. Start the Local Admin UI

```bash
envvault admin start
```

Open the printed localhost URL. The URL contains a local admin token used by the
browser UI when it calls EnvVault APIs for that server run.

The UI can add credentials and create inject or proxy profiles. It does not
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

## 4. Create an Inject Profile

Add an inject profile that maps a local profile name to the stored credential:

```bash
envvault inject add openai/dev \
  --credential openai-key/dev \
  --project-binding none
```

Use a repository-safe reference with the variable name expected by the app:

```dotenv
OPENAI_API_KEY=envvault://openai/dev/value
```

You can keep that line in `.env`, or skip creating a file and pass it directly
at launch:

```bash
envvault exec \
  --env OPENAI_API_KEY=envvault://openai/dev/value \
  -- npm run dev
```

## 5. Run the App

```bash
envvault exec --env-file .env -- npm run dev
envvault exec --env-file .env -- npm start
```

`envvault exec` reads the `.env` file, resolves `envvault://openai/dev/value`
from the OS credential store through the local profile policy, and launches the
child process with `OPENAI_API_KEY` populated.

This mode intentionally passes the raw credential to the child process
environment. It is the most compatible path and works with SDKs that expect a
normal API key environment variable.

## 6. Advanced: API Proxy Mode

Use a proxy profile when the app or SDK accepts a custom base URL and bearer
token, and you do not want to pass the real provider key to the child process.

Add a localhost proxy profile:

```bash
envvault proxy add openai/dev \
  --credential openai-key/dev \
  --provider generic \
  --target https://api.openai.com/v1 \
  --allow-path /chat/completions \
  --allow-path /responses \
  --allow-path /embeddings \
  --allow-method POST
```

The command prints a generic `.env` snippet:

```dotenv
ENVVAULT_PROXY_URL=envvault://openai/dev/base-url
ENVVAULT_PROXY_TOKEN=envvault://openai/dev/token
```

The Admin UI shows the same snippet with a copy button for proxy profiles.

Use the generated right-hand references with the variable names expected by the
app:

```dotenv
OPENAI_BASE_URL=envvault://openai/dev/base-url
OPENAI_API_KEY=envvault://openai/dev/token
```

`base-url` and `token` are EnvVault-generated proxy outputs. They are not
separate credentials to register.

At runtime, `envvault exec` starts a localhost proxy, rewrites
`OPENAI_BASE_URL` to that proxy, and rewrites `OPENAI_API_KEY` to a local-only
bearer token. The proxy adds the real provider key only for requests matching
the profile allowlist.

Proxy mode reduces provider-key exposure, but it also requires separate local
environment variables for the provider base URL. Use inject mode when you want
the simplest local/prod environment shape.

## 7. Inspect Health

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

## 8. Generate Shell Completion

```bash
envvault completion bash
envvault completion zsh
envvault completion fish
envvault completion powershell
```

Write the generated script to the completion location used by your shell.

## 9. Install The Agent Skill

EnvVault includes an agent skill for tools that need to launch commands with
EnvVault, configure profiles, or debug `envvault://` references.

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
