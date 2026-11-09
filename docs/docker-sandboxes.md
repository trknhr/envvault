# Docker Sandboxes host-side credentials

EnvVault can supply credentials to Docker Sandboxes (`sbx`) through its dynamic
secret command interface. The helper is the EnvVault CLI itself:
`envvault credential resolve envvault://<credential>`.

This integration is separate from `envvault sandbox run`. Docker owns request
matching, header injection, placeholders, and refresh policy. EnvVault reads the
selected direct credential from the host OS credential store. No EnvVault proxy
profile is required, and `sbx --ref` does not accept EnvVault references.

## Setup

Use a build of EnvVault that includes `credential resolve`, and a version of
`sbx secret set` with `--command` support. Store the credential interactively:

```bash
envvault credential set app/dev
```

Register the host command with Docker. This example assumes the new EnvVault
binary is installed at `/opt/homebrew/bin/envvault`; substitute its actual
absolute path if different:

```bash
sbx secret set openai \
  --sandbox my-sandbox \
  --command '/opt/homebrew/bin/envvault credential resolve envvault://app/dev' \
  --refresh on-demand
```

`my-sandbox` is the intended Docker sandbox name; replace it for your setup.
Docker verifies the command during registration. The command emits only the
credential bytes, without a newline, and exits unsuccessfully on lookup or
output failure. Do not run the resolver manually to inspect its output or
redirect it to logs. It refuses terminal output. Empty values, control
characters, and surrounding whitespace are rejected. Only direct credential
references work; proxy `/token` and `/base-url` outputs are rejected.

The host account running Docker must be able to access EnvVault's OS credential
store. Refresh can fail if the store is locked or requires interaction.

## Request flow

1. Docker invokes the configured command on the host.
2. EnvVault retrieves the selected credential from the OS store.
3. Docker's proxy applies the service's credential injection rules.
4. The application uses Docker's placeholder and its normal provider URL.

For a custom API, use Docker's `secret set-custom --command` flow and configure
the target hosts and environment variable there. Use the placeholder supplied
by Docker; an `envvault://` reference is an input to the host helper, not the
application's placeholder in this integration.

Docker runs helpers in a fresh temporary directory. Keep the installed binary,
its configuration, and the host temporary directory outside sandbox-writable
mounts. Never register `go run`, a helper script, or an executable from a shared
project directory as a production resolver.

## Validation scope

Automated tests exercise EnvVault's resolver contract with an in-memory store:
exact output, invalid references and header values, unavailable credentials,
terminal refusal, redacted errors, write failures, and buffer clearing. They do
not verify Docker's proxy injection or OS-store access by the Docker daemon.
Validate those separately with a disposable sandbox and a test credential
before relying on the integration. No real provider key is needed for unit
tests.

See [Docker's dynamic secret documentation](https://docs.docker.com/ai/sandboxes/configuration/credentials/#use-a-dynamic-secret-source)
for service matching, verification, caching, and custom-secret behavior.
