---
name: envvault
description: Use when launching local development tools with EnvVault, resolving envvault:// references, configuring API proxy or raw inject profiles, or debugging EnvVault CLI/env-file setup. Assumes envvault is installed.
---

# EnvVault

EnvVault keeps real credentials in the OS credential store and resolves
repository-safe `envvault://` references only when launching a child process.

## Commands

- Start UI: `envvault admin start`
- Add credential: `printf 'secret\n' | envvault credential add <credential-name> --value-stdin`
- Add proxy profile: `envvault proxy add <profile> --credential <credential-name> --provider generic --target <url> --allow-path <path> --allow-method <method>`
- Add raw inject profile: `envvault inject add <profile> --credential <credential-name>`
- List state: `envvault credential list`, `envvault profile list`
- Launch app: `envvault exec --env KEY=envvault://profile/output -- <command>` or `envvault exec --env-file .env -- <command>`
- Inspect state: `envvault doctor`, `envvault admin status`, `envvault reset --dry-run`

For credential workflows, stay within the admin, credential, proxy, inject,
exec, doctor, and reset commands.

## Reference Forms

Proxy profiles output values like this:

```dotenv
OPENAI_BASE_URL=envvault://openai/dev/base-url
OPENAI_API_KEY=envvault://openai/dev/token
```

Raw inject fallback:

```dotenv
DATABASE_URL=envvault://database/dev/value
```

Use the variable names the app expects; the right-hand side is the EnvVault
reference. Proxy `base-url` and `token` are generated outputs, not credentials
to register.

## Workflow

Prefer proxy mode when an SDK accepts a custom base URL and bearer token. The
child process receives a localhost URL and local token; EnvVault adds the real
provider key only for allowlisted requests.

Use raw inject only when proxying is impossible. Raw inject intentionally gives
the credential value to the child process.

When using the shell for checks, put the child command after `--` and use
`sh -lc` for shell expansion:

```bash
envvault exec --env OPENAI_API_KEY=envvault://openai/dev/token -- sh -lc 'test -n "$OPENAI_API_KEY" && echo OK'
```

Avoid printing actual credential values. Check presence, length, or make a
provider request through the app instead.

## Common Mistakes

- `--exec-file` is wrong; use `--env-file`.
- `envvalut://` is a typo; the scheme is `envvault://`.
- `envvault exec` requires `--` before the child command.
- `sh 'echo $VAR'` is wrong; use `sh -lc 'echo "$VAR"'`.
- A value is resolved only when the whole env value is an `envvault://...`
  reference.
