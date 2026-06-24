# Profiles

Profiles are local trusted policy. Repository files may reference a profile with `credlease://<name>`, but they cannot widen the profile's scope, resource, TTL, purpose, redirect targets, or project binding.

## Kinds

`process` profiles issue short-lived credentials for a child process launched by `credlease exec`.

`browser-session` profiles issue a bootstrap credential for `credlease open`. The target backend exchanges that credential for a one-time code and then creates its own web session cookie.

## Policy Fields

- `resource`: The audience or backend URL the leased credential is valid for.
- `scope`: The maximum scopes Credlease can request for this profile.
- `ttl` and `max_ttl`: The requested and maximum lifetime. TTL is clamped by trusted profile policy, not by repository input.
- `project binding`: The local approval tying profile use to a path hash or git remote plus root.
- `claims`: Optional custom claims. Credlease-owned claim names use the `credlease_` prefix, and standard JWT claim names are reserved.

## Secret Storage

Each profile has a separate parent key stored in the OS credential store. The config file stores non-secret policy and metadata only. Credlease does not write raw parent keys, signing keys, issued JWTs, login codes, or Authorization header values into profile files.

## Project Binding

The default binding mode is `git-remote-and-root`. First use requires a TTY confirmation that records the approved project identity in user config. Non-interactive use fails closed when the binding is unknown.

Use `none` only for low-risk local workflows. Use `path-hash` when a project has no git remote but still needs local binding.
