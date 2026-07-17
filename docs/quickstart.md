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
envvault credential set app/dev
```

Enter the value at the hidden terminal prompt. EnvVault does not accept the
credential as a positional argument, keeping it out of shell history and
process arguments.

For non-interactive scripts, pass the value over stdin explicitly:

```bash
printf 'secret-value\n' | envvault credential set app/dev \
  --value-stdin
```

You can also add or update the credential from the Admin UI.

To remove it later, use `envvault credential delete app/dev`. EnvVault refuses
when a profile still references the credential.
`envvault credential delete app/dev --cascade` removes both the credential and
every dependent profile.

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

## 6. Advanced: Isolated Home Files

Some tools always read a credential or configuration file from the user's home
directory. Keep a repository-safe source file in the project with only the
secret fields represented by EnvVault references. For example, create
`config/hogehoge.yaml`:

```yaml
endpoint: https://api.example.com
token: envvault://app/dev
```

Then run the tool through EnvVault:

```bash
envvault exec \
  --home-file .hogehoge=config/hogehoge.yaml \
  -- your-command
```

The left-hand `DEST` is a safe relative path inside a private, otherwise empty
temporary home. The right-hand `SOURCE` is resolved relative to the invocation
working directory; an absolute source path is also allowed. `~` is not expanded,
so use an already-expanded path such as `"$HOME/.hogehoge"` when the source
really belongs in the normal home:

```bash
envvault exec \
  --home-file ".hogehoge=$HOME/.hogehoge" \
  -- your-command
```

A bare path uses the same relative source and destination. Because a single
dotfile has no format extension, this example reads `./.hogehoge` as JSON and
writes it to `~/.hogehoge` under the isolated home:

```bash
envvault exec --home-file .hogehoge -- your-command
```

Supported template formats are selected from the source filename:

- `.json` for JSON
- `.yaml` or `.yml` for YAML
- `.toml` for TOML
- no extension or a single dotfile name for JSON

An unknown extension is rejected. EnvVault parses the source, recursively
resolves values, and serializes the result at `DEST`. Only a string value that
consists entirely of a direct `envvault://<credential>` reference is replaced.
Keys are never resolved. Partial strings such as
`"Bearer envvault://app/dev"` and proxy `/base-url` or `/token` outputs are
rejected. A credential remains a string even if its text looks like JSON, YAML,
or TOML. YAML anchors, aliases, and merge keys are not supported; mapping keys
must be strings.

The result is normalized output; comments, quoting, whitespace, and key order
may change. The source file itself is never modified, and changes made by the
child are not written back. Templates are limited to 4 MiB and 128 nesting
levels. Duplicate keys, multiple JSON or YAML documents, non-regular source
files, source symlinks, and credential values that are not valid UTF-8 are
rejected before the child starts.

Destination paths must remain relative to the isolated home. Absolute
destinations, `~`, `..`, empty path segments, and drive or volume prefixes are
rejected. Repeat `--home-file` when a command needs more than one file or
format:

```bash
envvault exec \
  --home-file .config/example/auth.json=config/auth.json \
  --home-file .config/example/settings.toml=config/settings.toml \
  -- your-command
```

For a tool whose entire file is one raw credential, the earlier shorthand is
still available:

```bash
envvault exec --home-file .token=envvault://app/dev -- your-command
```

Temporary directories are private and resolved files are readable and writable
only by the current user.

The child process receives the isolated home through the platform's home and
config environment variables. EnvVault creates the workspace below its private
cache directory and copies no unrelated real-home contents. The child therefore
cannot rely on other configuration files being present in the isolated home.
The child can read the resolved credential files. EnvVault removes the isolated
home when the child exits normally. If EnvVault is forcibly terminated or the
system fails, `envvault doctor --repair` removes stale isolated-home workspaces.

This mode is intended for foreground tools that honor those environment
variables. It is not a filesystem sandbox: a tool that resolves the OS account
home independently can still reach the real home, and a daemonized descendant
does not extend the isolated home's lifetime after the direct child exits.

## 7. Advanced: API Proxy Mode

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

## 8. Inspect Health

```bash
envvault doctor
envvault credential list
envvault proxy list
envvault doctor --repair
envvault reset --dry-run
```

`doctor` reports local state health. `doctor --repair` removes stale EnvVault
runtime locks, temporary files, and isolated-home workspaces before re-checking
health. `reset --dry-run` shows EnvVault-owned files and keyring entries that
would be removed.

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
