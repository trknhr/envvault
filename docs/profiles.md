# Profiles

Profiles are local trusted policy. Repository files may reference a profile with
`envvault://...`, but they cannot change the profile's target URL, allowlist,
credential binding, token lifetime, or project binding.

## Kinds

`provider-proxy` profiles start a localhost proxy during `envvault exec`. The
child process receives a local base URL and local-only bearer token. EnvVault
adds the real provider key only when forwarding allowed requests.

`inject` profiles resolve `envvault://<profile>/value` to a named credential
value. This is the raw injection fallback for tools that cannot use a localhost
proxy.

## Policy Fields

- `provider`: The proxy provider type. The MVP supports `generic` and
  `openai-compatible`.
- `credential`: The named OS credential store entry used by a provider-proxy or
  inject profile.
- `auth_mode`: The provider-proxy authentication mode. The MVP supports
  `bearer`.
- `target_url`: The fixed provider API base URL the local proxy forwards to.
- `allowed_paths` and `allowed_methods`: The proxy allowlist enforced before the
  real provider key is added.
- `local_token_ttl`: The local proxy bearer token lifetime for a child process.
- `project binding`: The local approval tying profile use to a path hash or git
  remote plus root.

## Secret Storage

Credentials are stored in the OS credential store. Provider-proxy and inject
profiles point at named credential values. The config file stores non-secret
policy and metadata only.

EnvVault does not write provider API keys, database URLs, local proxy tokens, or
Authorization header values into profile files.

## Project Binding

The default binding mode is `git-remote-and-root`. First use requires a TTY
confirmation that records the approved project identity in user config.
Non-interactive use fails closed when the binding is unknown.

Use `none` only for low-risk local workflows. Use `path-hash` when a project has
no git remote but still needs local binding.
