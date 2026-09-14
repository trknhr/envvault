# Threat Model

EnvVault protects long-lived local credential material from routine project and
`.env` exposure. It does not defend against a fully compromised OS user account.

## Assets

- Credential values stored in the OS credential store.
- Credential files inside temporary isolated-home workspaces while a child
  process is running.
- Local proxy bearer tokens while the child process is running.
- URL-preserving outbound proxy capabilities and ephemeral CA private keys
  while a sandbox lease is active.
- External sandbox plugin and session capabilities while a lease is active.
- Persistent native agent OAuth state stored under EnvVault's private data
  directory.
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
- Host-side outbound broker: terminates configured HTTP/HTTPS routes, enforces
  destination/method/path policy, and adds provider credentials while keeping
  its ephemeral CA private key outside the sandbox.
- Experimental Docker sandbox: receives a short-lived gateway capability but
  not the upstream credential in brokered mode.
- Native agent auth mount: an explicitly selected, writable, profile-specific
  agent home containing OAuth tokens and persistent agent configuration.
- External sandbox control plane: trusted to own the plugin stdin/stdout,
  inject selected capability values, apply egress policy, and revoke leases.
- External session runtime: the host executable selected by `sandbox exec` is
  trusted to report project/container identity, revalidate the target, and
  inject temporary capabilities into only the requested process.
- External agent sandbox: untrusted; receives selected gateway capabilities but
  never the plugin control channel or upstream credential.
- Docker daemon: trusted host component that creates, starts, stops, and removes
  the application container.
- Third-party provider API: receives the real provider API key from the child
  process or proxy.

## In Scope

- Accidental commit of `.env` files containing `envvault://` references.
- Third-party SDKs that expect normal API key environment variables.
- Third-party tools that require credential files at fixed paths below their
  home directory.
- Third-party SDKs that can be configured with both a custom base URL and bearer
  token.
- Proxy-aware sandbox applications that must retain the provider's original
  URL and can send a request without possessing the real bearer credential.
- Repository changes that try to request a different credential, proxy target
  URL, method, or path.
- Child processes that can inspect their own environment.
- Application containers that inspect their environment, image metadata, and
  mounted workspace.
- Application containers explicitly granted a native agent auth profile that
  inspect or modify that persistent profile.
- Existing agent sandboxes integrated through a trusted host-side plugin or
  session runtime.

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
- Protecting native agent OAuth state from a container after the operator
  explicitly selects `--agent-auth native`.
- Default-deny Docker egress, DNS enforcement, cloud metadata blocking, and
  isolation from every host service in experimental `brokered` mode.
- Transparent interception for clients that ignore proxy settings, use TLS
  certificate pinning, or require an unsupported language-specific trust store.
- Docker daemon compromise or container escape.
- A malicious or compromised external sandbox control plane. It owns the
  temporary capabilities and is part of the trusted computing base.
- A malicious external session runtime or native credentials and mounts
  already provided by agent-infra. `sandbox exec` does not remove or isolate
  that existing state.
- Default-deny enforcement by a third-party sandbox platform. The generic
  plugin reports only `brokered`.

## Security Controls

- Credential values are stored in the OS credential store.
- `envvault inspect` scans local file contents in-process without Git history,
  network verification, or symlink traversal. Its output model contains only
  path, location, rule, and confidence metadata; matched values are discarded.
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
- `sandbox run --all` rechecks project bindings, selects only provider-proxy
  profiles allowed for the current project, and fails when none are eligible.
  Because newly added eligible profiles expand its authority automatically,
  explicit profile names remain the least-authority, reproducible choice.
- Audit records are metadata-only.
- Docker sandbox mode rejects direct credential references unless the exact
  reference belongs to an attached outbound profile or
  `--allow-materialized-secrets` is explicit. Proxy mode places only the local
  gateway URL and short-lived token in the container environment and metadata.
- URL-preserving outbound mode places a non-secret, late-bound credential
  reference, a short-lived authenticated proxy URL, and an ephemeral public CA
  in the sandbox. The broker requires the exact reference in the configured
  bearer field, fixes configured destinations, checks exact methods and paths,
  removes hop-by-hop headers, replaces only that bearer field, and does not
  follow credential-bearing redirects. Its CA private key and provider
  credential remain host-side.
- The outbound broker refuses unconfigured private, loopback, link-local, and
  unspecified destinations. This prevents the broker itself from becoming a
  general private-network relay; it does not block direct container traffic.
- Native agent auth is explicit, uses a validated agent adapter and profile
  name, stores state below EnvVault's private data directory, rejects symlinked
  state paths, and forces private directory permissions. It never mounts the
  operator's normal agent home implicitly.
- The Docker runtime uses bridge networking, a read-only root filesystem,
  ephemeral HOME and `/tmp`, dropped capabilities, `no-new-privileges`, PID,
  memory, and CPU limits, and a workspace mount. Native mode adds one selected
  agent-state mount. It does not mount the host home, OS credential store, or
  Docker socket.
- Docker containers, gateway listeners, and credential leases are cleaned up
  after normal exit, lifecycle failure, or Ctrl-C.
- The external sandbox plugin accepts only versioned, bounded NDJSON messages,
  rejects direct credential outputs and duplicate environment mappings, binds
  connection grants to the supplied sandbox identity, and revokes every lease
  on `close`, EOF, or process cancellation.
- External sandbox sessions accept only explicitly selected provider-proxy
  output references and reject raw credentials and host-control variables.
  The agent-infra adapter requires a versioned, bounded preparation descriptor,
  matches the host project identity, and pins execution to a full container ID.
- Session capability values pass through the trusted runtime child's
  environment, not command arguments, token files, or container creation
  metadata. Exit, cancellation, launch failure, and expiry revoke the lease
  without stopping or deleting the existing sandbox. There is no automatic
  renewal.

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

The URL-preserving proxy capability is also visible in the sandbox environment
and Docker metadata. A sandbox can use it for every attached route until
cleanup or expiry. The public CA is not a credential, but installing it lets
the trusted broker terminate TLS for configured destinations and observe
allowed request metadata and bodies. A client can bypass this cooperative path
by ignoring `HTTP(S)_PROXY` because direct bridge egress remains available. The
broker's private-destination check protects the host-side proxy only; it is not
a Docker firewall.

The Docker sandbox token is likewise visible to the application and in Docker
container metadata. The upstream credential is not delivered in brokered mode,
but the container retains direct bridge egress and may reach unrelated internet
or host services. The temporary host gateway uses a random token and allowlist;
it is not an egress firewall. A host crash or forced EnvVault termination may
leave a labeled container requiring manual review and removal.

Native agent auth intentionally gives the container read-write access to an
OAuth-bearing agent home. A malicious image or repository command can
exfiltrate refresh material through direct egress, log the state, delete it, or
persist poisoned configuration for future invocations. A separate profile
limits cross-project reuse but does not make the credential secret from the
selected sandbox.

The external sandbox plugin returns bearer capabilities to its trusted control
plane. A platform that logs protocol responses, reuses a capability across
sandboxes, exposes the plugin pipes to the sandbox, or fails to apply the
returned egress restrictions weakens the boundary. Process EOF performs
best-effort cleanup, but an uncatchable process or host failure may leave a
gateway alive until its short TTL expires.

External sandbox sessions report `brokered`, not network-enforced isolation.
The launched process and trusted host runtime can read the temporary token;
host/container process inspection or application logging may expose it.
The agent-infra adapter binds an ephemeral gateway to `0.0.0.0`, advertised as
`host.docker.internal`, so its token-protected listener is not loopback-only.
Use a trusted host/network and do not publish it externally. Existing native
auth mounts and egress remain unchanged. Detached processes may survive the
session, but revoked capabilities no longer grant API access. See
[External Sandbox Sessions](/sandbox-exec) for supported platforms and limits.
