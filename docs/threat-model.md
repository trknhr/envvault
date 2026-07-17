# Threat Model

EnvVault protects long-lived local credential material from routine project and
`.env` exposure. It does not defend against a fully compromised OS user account.

## Assets

- Credential values stored in the OS credential store.
- Credential files inside temporary isolated-home workspaces while a child
  process is running.
- Local proxy bearer tokens while the child process is running.
- EnvVault config policy and project-binding approvals.

## Trust Boundaries

- OS credential store: stores long-lived raw secrets.
- EnvVault config directory: stores non-secret settings and optional proxy
  policy.
- Child process environment: receives resolved credential values or local proxy
  bearer tokens.
- Isolated home workspace: receives credential values requested with
  `--home-file` and becomes the child process's home without copying or
  writing the requested destination under the real home directory.
- Localhost provider proxy: accepts local proxy bearer tokens and adds provider
  API keys for allowlisted requests.
- Third-party provider API: receives the real provider API key from the child
  process or proxy.

## In Scope

- Accidental commit of `.env` files containing `envvault://` references.
- Third-party SDKs that expect normal API key environment variables.
- Third-party tools that require credential files at fixed paths below their
  home directory.
- Third-party SDKs that can be configured with both a custom base URL and bearer
  token.
- Repository changes that try to request a different credential, proxy target
  URL, method, or path.
- Child processes that can inspect their own environment.

## Out of Scope

- Malicious code running as the same OS user with arbitrary process and keychain
  access.
- Kernel, hypervisor, firmware, or hardware compromise.
- Browser compromise or malicious browser extensions.
- Application-level data written using a valid credential.
- DLP for prompts, stdout, stderr, HTTP request bodies, or third-party
  application logs.
- Keeping a credential out of the child process when an SDK or tool requires
  the raw credential directly and cannot be pointed at the EnvVault localhost
  proxy.

## Security Controls

- Credential values are stored in the OS credential store.
- Direct references use strict `envvault://<credential>` parsing.
- `.env` references reject query strings, fragments, path traversal, and
  percent-encoded separators.
- `--home-file` accepts only safe relative destination paths and creates a
  private, otherwise empty home. Template sources may be relative to the
  invocation working directory or absolute; source files must be regular files
  and may not be symlinks.
- Home-file JSON, YAML, and TOML resolution replaces only whole-string direct
  credential references in values, never keys. It rejects embedded or proxy
  references, ambiguous input, non-string YAML mapping keys, and unsupported
  YAML anchors, aliases, and merge keys; credentials are safely encoded as
  strings and results are written with user-only permissions. Source templates
  are not modified or written back.
- Isolated-home workspaces are removed after normal child exit. Stale
  workspaces left by forced termination or system failure are removed by
  `envvault doctor --repair`.
- Optional proxy policy fixes target URL, allowed HTTP methods, allowed paths,
  and local token lifetime.
- Proxy `.env` references split proxy base URLs from local-only bearer tokens.
- Non-interactive unapproved project bindings fail closed for proxy use.
- Audit records are metadata-only.

## Residual Risk

Direct credential mode places the credential value in the child process
environment. It improves repository and `.env` hygiene but does not hide that
credential from the launched process.

Isolated home-file mode likewise does not hide a credential from the child: the
child can read every injected file. A forced termination or system failure can
leave the private workspace on disk until `envvault doctor --repair` removes it.
The source template contains references rather than secrets and remains
unchanged; child modifications to the normalized resolved copy are discarded.
Because the isolated home starts empty, a child that needs unrelated files from
the real home must be configured explicitly rather than relying on them.
The isolation changes home and config environment variables; it does not mount
or sandbox the filesystem. A child that independently resolves the OS account
home can still access it. The workspace lifetime follows the direct child, so a
daemonized descendant does not keep the workspace alive.

Local proxy tokens are bearer tokens. Anyone who obtains one can use it until it
expires, subject to the proxy allowlist.
