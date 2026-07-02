# Threat Model

EnvVault Local MVP protects long-lived local credential material from routine
project, `.env`, and child-process exposure. It does not defend against a fully
compromised OS user account.

## Assets

- Provider API keys for proxy profiles.
- Raw credential values for inject profiles.
- Local proxy bearer tokens while the child process is running.
- EnvVault config policy and project-binding approvals.

## Trust Boundaries

- OS credential store: stores long-lived raw secrets.
- EnvVault config directory: stores policy and non-secret settings.
- Child process environment: receives local proxy bearer tokens or raw inject
  values when explicitly configured.
- Localhost provider proxy: accepts local proxy bearer tokens and injects
  provider API keys for allowlisted requests.
- Third-party provider API: receives the real provider API key from the proxy.

## In Scope

- Accidental commit of `.env` files containing `envvault://` references.
- Third-party SDKs that can be configured with both a custom base URL and bearer
  token.
- Tools that require raw credentials and are configured through explicit inject
  profiles.
- Repository changes that try to request a different credential, target URL,
  method, path, or project binding.
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

- Provider credentials are stored in the OS credential store.
- Profiles are local trusted policy, not repository-controlled policy.
- Project binding links profiles to an approved path hash or git root and
  remote.
- Non-interactive unapproved project bindings fail closed.
- Provider proxy policy fixes target URL, allowed HTTP methods, allowed paths,
  and local token lifetime.
- Inject profiles require an explicit `/value` reference and project binding
  before a raw credential is passed to a child process.
- `.env` references reject query strings, fragments, path traversal, and
  percent-encoded separators.
- Proxy `.env` references split proxy base URLs from local-only bearer tokens.
- Audit records are metadata-only.

## Residual Risk

Local proxy tokens are bearer tokens. Anyone who obtains one can use it until it
expires, subject to the proxy allowlist.

Raw inject mode places the credential value in the child process environment. It
improves repository and `.env` hygiene but does not hide that credential from the
launched process.
