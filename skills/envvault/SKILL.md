---
name: envvault
description: Use when launching local development tools with EnvVault, resolving envvault:// references, injecting isolated home files, configuring optional API proxies, or debugging EnvVault CLI setup. Assumes envvault is installed.
---

# EnvVault

EnvVault keeps real credentials in the OS credential store and resolves
repository-safe `envvault://` references only when launching a child process.

## Commands

- Start UI: `envvault admin start`
- Set credential interactively: `envvault credential set <credential-name>`
- Set credential from stdin: `printf 'secret\n' | envvault credential set <credential-name> --value-stdin`
- Delete credential: `envvault credential delete <credential-name>`
- Add proxy: `envvault proxy add <proxy-name> --credential <credential-name> --provider generic --target <url> --allow-path <path> --allow-method <method>`
- List state: `envvault credential list`, `envvault proxy list`
- Launch app: `envvault exec --env KEY=envvault://<credential> -- <command>` or `envvault exec --env-file .env -- <command>`
- Resolve a home-file template: `envvault exec --home-file <destination>=<source> -- <command>`
- Inspect state: `envvault doctor`, `envvault admin status`, `envvault reset --dry-run`

For local credential workflows, stay within the admin, credential, proxy, exec,
doctor, and reset commands.

## Reference Forms

Default direct credential:

```dotenv
APP_SECRET=envvault://app/dev
DATABASE_URL=envvault://database/dev
```

Optional proxy outputs:

```dotenv
APP_BASE_URL=envvault://api-proxy/dev/base-url
APP_API_TOKEN=envvault://api-proxy/dev/token
```

Use the variable names the app expects; the right-hand side is the EnvVault
reference. Proxy `base-url` and `token` are generated outputs, not credentials
to register.

## Workflow

Prefer direct credential references for SDKs that expect normal API key or
database URL environment variables. This gives the child process the real
credential at launch.

Use proxy mode only when an SDK accepts a custom base URL and bearer token. The
child process receives a localhost URL and local token; EnvVault adds the real
upstream credential only for allowlisted requests.

Use repeatable `--home-file` options when a tool always reads credentials or
configuration from its home directory. Keep a non-secret source in the project:

```yaml
endpoint: https://api.example.com
token: envvault://app/dev
```

```bash
envvault exec \
  --home-file .hogehoge=config/hogehoge.yaml \
  -- <command>
```

The destination must be safe and relative to the isolated home. A relative
source is resolved from the invocation working directory; an absolute source is
also allowed. Formats are selected from the source filename: `.json`, `.yaml`,
`.yml`, or `.toml`. Extensionless names and single dotfiles default to JSON;
unknown extensions are rejected. A bare `--home-file .hogehoge` uses
`./.hogehoge` as both source and destination.

EnvVault recursively resolves only whole-string direct credential references in
values, never keys, and writes normalized output to the isolated home. Comments,
formatting, and key order may change. YAML anchors, aliases, and merge keys are
unsupported, and mapping keys must be strings. The source is not modified
and child changes are not written back. The child can read the resolved files.
Normal child exit removes the workspace; after a forced termination or system
failure, use `envvault doctor --repair` to remove stale workspaces. For a file
that consists entirely of one raw secret, use
`--home-file .token=envvault://app/dev`.

Use this for foreground tools that honor home-directory environment variables.
It is not a filesystem sandbox, and daemonized descendants do not extend the
workspace lifetime after the direct child exits.

When using the shell for checks, put the child command after `--` and use
`sh -lc` for shell expansion:

```bash
envvault exec --env APP_SECRET=envvault://app/dev -- sh -lc 'test -n "$APP_SECRET" && echo OK'
```

Do not print credential-bearing environment values. Avoid `echo "$API_KEY"`,
`printenv`, `env`, `set`, or similar commands in a child process that may
contain secrets. Check presence only, print fixed strings like `OK`, or make a
provider request through the app instead.

## Common Mistakes

- `--exec-file` is wrong; use `--env-file`.
- `envvalut://` is a typo; the scheme is `envvault://`.
- `envvault exec` requires `--` before the child command.
- `--home-file` destinations are relative to the isolated home; absolute paths,
  `~`, `..`, and empty path segments are rejected.
- Relative `--home-file` sources use the command's invocation working
  directory, not the real home. Use `"$HOME/path"` for an explicit home source.
- References must occupy the complete string value. Template keys are not
  resolved, and embedded references or proxy outputs are rejected.
- Do not expect dotfiles from the real home inside the isolated home.
- `sh -lc 'echo "$VAR"'` can leak secrets; use
  `sh -lc 'test -n "$VAR" && echo OK'` for presence checks.
- A value is resolved only when the whole env value is an `envvault://...`
  reference.
- Public `.env` references use `envvault://<credential>`.
