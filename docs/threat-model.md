# Threat Model

EnvVault Local MVP protects long-lived local credential material from routine project, `.env`, and child-process exposure. It does not defend against a fully compromised OS user account.

## Assets

- Talos parent API keys for each profile.
- Provider API keys for third-party proxy profiles.
- Talos HMAC secret.
- JWT signing private key or equivalent signing material.
- Issued short-lived JWTs while valid.
- Local proxy bearer tokens while the child process is running.
- Browser bootstrap JWTs.
- Browser one-time login codes.
- Browser session cookies created by the target backend.
- EnvVault config policy and project-binding approvals.

## Trust Boundaries

- OS credential store: stores long-lived raw secrets.
- EnvVault config directory: stores policy and non-secret settings.
- Talos SQLite database: stores metadata and hashes, not raw parent keys.
- Child process environment: receives only short-lived leased tokens.
- Localhost provider proxy: accepts local proxy bearer tokens and injects provider API keys for allowlisted requests.
- Third-party provider API: receives the real provider API key from the proxy.
- Browser launch URL: receives only an opaque one-time login code, not a JWT.
- Resource server or backend: validates JWT signature, issuer, expiry, scope, resource, and purpose.

## In Scope

- Accidental commit of `.env` files containing `envvault://` references.
- Third-party SDKs that can be configured with both a custom base URL and bearer token.
- Repository changes that try to request broader scope, resource, TTL, or redirect behavior.
- Child processes that can inspect their own environment.
- Backend access logs and browser URL history that may see browser login URLs.
- Lost or copied SQLite files.
- Talos startup, shutdown, and loopback exposure during local issuance.

## Out of Scope

- Malicious code running as the same OS user with arbitrary process and keychain access.
- Kernel, hypervisor, firmware, or hardware compromise.
- Browser compromise or malicious browser extensions.
- Application-level data written using a valid short-lived token.
- DLP for prompts, stdout, stderr, HTTP request bodies, or third-party application logs.
- Keeping a provider key out of the child process when an SDK or tool requires the raw provider key directly and cannot be pointed at the EnvVault localhost proxy.

## Security Controls

- Raw parent keys are stored only in the OS credential store.
- Issued JWTs are not cached on disk by EnvVault.
- Profiles are local trusted policy, not repository-controlled policy.
- Project binding links profiles to an approved path hash or git root and remote.
- Non-interactive unapproved project bindings fail closed.
- Profile policy fixes resource, scopes, and TTL ceilings.
- Provider proxy policy fixes target URL, allowed HTTP methods, allowed paths, and local token lifetime.
- `.env` references reject query strings, fragments, path traversal, and percent-encoded separators.
- Third-party `.env` references split proxy base URLs from local-only bearer tokens.
- Browser login uses an Authorization header for the bootstrap JWT and a short-lived one-time code in the URL.
- Browser launch URLs must match the profile's complete URL and allowed hosts.
- Audit records are metadata-only.

## Residual Risk

Leased tokens and local proxy tokens are bearer tokens. Anyone who obtains one can use it until it expires, subject to scope, resource, or proxy allowlist checks. Keep TTLs short and grant only the scopes or paths needed by a workflow.

Local MVP trust is per machine and per OS user. For remote production services, register the local JWKS explicitly or use a future centralized STS rather than accepting arbitrary local issuer keys.
