# Quickstart

This page describes the default EnvVault local workflow:

1. Store a real credential in the OS credential store.
2. Keep only an `envvault://<credential>` reference in `.env`.
3. Launch the app through `envvault exec`.

Canonical public references are:

- Direct credential: `envvault://<credential>`
- Proxy base URL: `envvault://<proxy>/base-url`
- Proxy token: `envvault://<proxy>/token`

Do not add `/value` to `.env` references. `/value` is only part of internal OS
credential store account names used by cleanup tooling and diagnostics.

Use proxy mode as an advanced option when an SDK accepts a custom base URL and
bearer token.

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

The UI can add credentials and create optional proxies. It does not display
stored credential values.

Use `envvault admin status` to check the background process and
`envvault admin stop` to stop it. `envvault admin serve` is available for
foreground debugging.

The CLI commands below are equivalent paths for scripting or repeatable local
testing.

## 3. Add a Credential

Store the real credential in the OS credential store:

```bash
printf 'secret-value\n' | envvault credential add app/dev \
  --value-stdin
```

You can also add the credential from the Admin UI.

## 4. Add the Reference to `.env`

Use the environment variable name expected by the app, and make the value an
EnvVault reference:

```dotenv
APP_SECRET=envvault://app/dev
```

You can keep that line in `.env`, or skip creating a file and pass it directly
at launch:

```bash
envvault exec \
  --env APP_SECRET=envvault://app/dev \
  -- npm run dev
```

## 5. Run the App

```bash
envvault exec --env-file .env -- npm run dev
envvault exec --env-file .env -- npm start
```

`envvault exec` reads the `.env` file, resolves `envvault://app/dev` from the OS
credential store, and launches the child process with `APP_SECRET` populated.

This mode intentionally passes the raw credential to the child process
environment. It is the most compatible path and works with SDKs that expect a
normal API key environment variable.

## 6. Advanced: API Proxy Mode

Use proxy mode when the app or SDK accepts a custom base URL and bearer token,
and you do not want to pass the real upstream credential to the child process.

Add a localhost proxy:

```bash
envvault proxy add api-proxy/dev \
  --credential app/dev \
  --provider generic \
  --target https://api.example.com \
  --allow-path /v1/messages \
  --allow-method POST
```

The command prints a generic `.env` snippet:

```dotenv
ENVVAULT_PROXY_URL=envvault://api-proxy/dev/base-url
ENVVAULT_PROXY_TOKEN=envvault://api-proxy/dev/token
```

The Admin UI shows the same snippet with a copy button for proxies.

Use the generated right-hand references with the variable names expected by the
app:

```dotenv
APP_BASE_URL=envvault://api-proxy/dev/base-url
APP_API_TOKEN=envvault://api-proxy/dev/token
```

`base-url` and `token` are EnvVault-generated proxy outputs. They are not
separate credentials to register.

At runtime, `envvault exec` starts a localhost proxy, rewrites
`APP_BASE_URL` to that proxy, and rewrites `APP_API_TOKEN` to a local-only
bearer token. The proxy adds the real upstream credential only for requests
matching the allowlist.

Proxy mode reduces raw-secret exposure, but it also requires separate local
environment variables for the provider base URL.

## 7. Inspect Health

```bash
envvault doctor
envvault credential list
envvault proxy list
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
EnvVault, configure credentials or proxies, or debug `envvault://` references.

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
