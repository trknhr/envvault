# Threat Model

EnvVault Local protects long-lived local credential material from routine
project and `.env` exposure. It does not defend against a fully compromised OS
user account.

## Assets

- Credential values stored in the OS credential store.
- Local proxy bearer tokens while the child process is running.
- EnvVault config policy and project-binding approvals.

## Trust Boundaries

- OS credential store: stores long-lived raw secrets.
- EnvVault config directory: stores non-secret settings and optional proxy
  policy.
- Child process environment: receives resolved credential values or local proxy
  bearer tokens.
- Localhost provider proxy: accepts local proxy bearer tokens and adds provider
  API keys for allowlisted requests.
- Third-party provider API: receives the real provider API key from the child
  process or proxy.

## In Scope

- Accidental commit of `.env` files containing `envvault://` references.
- Third-party SDKs that expect normal API key environment variables.
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
- Keeping a provider key out of the child process when an SDK or tool requires
  the raw provider key directly and cannot be pointed at the EnvVault localhost
  proxy.

## Security Controls

- Credential values are stored in the OS credential store.
- Direct references use strict `envvault://<credential>` parsing.
- `.env` references reject query strings, fragments, path traversal, and
  percent-encoded separators.
- Optional proxy policy fixes target URL, allowed HTTP methods, allowed paths,
  and local token lifetime.
- Proxy `.env` references split proxy base URLs from local-only bearer tokens.
- Non-interactive unapproved project bindings fail closed for proxy use.
- Audit records are metadata-only.

## Residual Risk

Direct credential mode places the credential value in the child process
environment. It improves repository and `.env` hygiene but does not hide that
credential from the launched process.

Local proxy tokens are bearer tokens. Anyone who obtains one can use it until it
expires, subject to the proxy allowlist.
