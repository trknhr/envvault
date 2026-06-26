# Profiles

Profiles are local trusted policy. Repository files may reference a profile with `envvault://<name>`, but they cannot widen the profile's scope, resource, TTL, purpose, redirect targets, or project binding.

## Kinds

`process` profiles issue short-lived credentials for a child process launched by `envvault exec`.

`browser-session` profiles issue a bootstrap credential for `envvault open`. The target backend exchanges that credential for a one-time code and then creates its own web session cookie.

`provider-proxy` profiles start a localhost proxy for a third-party API during `envvault exec`. The child process receives a local base URL and local-only bearer token; EnvVault adds the real provider key only when forwarding allowed requests.

## Policy Fields

- `resource`: The audience or backend URL the leased credential is valid for.
- `scope`: The maximum scopes EnvVault can request for this profile.
- `ttl` and `max_ttl`: The requested and maximum lifetime. TTL is clamped by trusted profile policy, not by repository input.
- `project binding`: The local approval tying profile use to a path hash or git remote plus root.
- `claims`: Optional custom claims. EnvVault-owned claim names use the `envvault_` prefix, and standard JWT claim names are reserved.
- `provider`: The third-party proxy provider type. The MVP supports `openai-compatible`.
- `target_url`: The fixed provider API base URL the local proxy forwards to.
- `allowed_paths` and `allowed_methods`: The proxy allowlist enforced before the real provider key is added.
- `local_token_ttl`: The local proxy bearer token lifetime for a child process.

## Secret Storage

Each process or browser-session profile has a separate parent key stored in the OS credential store. Each provider-proxy profile stores its provider API key in the OS credential store. The config file stores non-secret policy and metadata only. EnvVault does not write raw parent keys, provider API keys, signing keys, issued JWTs, login codes, local proxy tokens, or Authorization header values into profile files.

## Project Binding

The default binding mode is `git-remote-and-root`. First use requires a TTY confirmation that records the approved project identity in user config. Non-interactive use fails closed when the binding is unknown.

Use `none` only for low-risk local workflows. Use `path-hash` when a project has no git remote but still needs local binding.
