---
name: envvault
description: Use when launching local development tools with EnvVault, resolving envvault:// references, configuring optional API proxies, or debugging EnvVault CLI/env-file setup. Assumes envvault is installed.
---

# EnvVault

EnvVault keeps real credentials in the OS credential store and resolves
repository-safe `envvault://` references only when launching a child process.

## Commands

- Start UI: `envvault admin start`
- Add credential: `printf 'secret\n' | envvault credential add <credential-name> --value-stdin`
- Add proxy: `envvault proxy add <proxy-name> --credential <credential-name> --provider generic --target <url> --allow-path <path> --allow-method <method>`
- List state: `envvault credential list`, `envvault proxy list`
- Launch app: `envvault exec --env KEY=envvault://<credential> -- <command>` or `envvault exec --env-file .env -- <command>`
- Inspect state: `envvault doctor`, `envvault admin status`, `envvault reset --dry-run`

For local credential workflows, stay within the admin, credential, proxy, exec,
doctor, and reset commands.

## Reference Forms

Default direct credential:

```dotenv
OPENAI_API_KEY=envvault://openai/dev
DATABASE_URL=envvault://database/dev
```

Optional proxy outputs:

```dotenv
OPENAI_BASE_URL=envvault://openai-proxy/dev/base-url
OPENAI_API_KEY=envvault://openai-proxy/dev/token
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
provider key only for allowlisted requests.

When using the shell for checks, put the child command after `--` and use
`sh -lc` for shell expansion:

```bash
envvault exec --env OPENAI_API_KEY=envvault://openai/dev -- sh -lc 'test -n "$OPENAI_API_KEY" && echo OK'
```

Do not print credential-bearing environment values. Avoid `echo "$API_KEY"`,
`printenv`, `env`, `set`, or similar commands in a child process that may
contain secrets. Check presence only, print fixed strings like `OK`, or make a
provider request through the app instead.

## Common Mistakes

- `--exec-file` is wrong; use `--env-file`.
- `envvalut://` is a typo; the scheme is `envvault://`.
- `envvault exec` requires `--` before the child command.
- `sh -lc 'echo "$VAR"'` can leak secrets; use
  `sh -lc 'test -n "$VAR" && echo OK'` for presence checks.
- A value is resolved only when the whole env value is an `envvault://...`
  reference.
- Public `.env` references use `envvault://<credential>`.
