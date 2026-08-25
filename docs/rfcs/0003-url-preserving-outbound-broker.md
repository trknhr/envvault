# RFC 0003: URL-preserving outbound broker

- Status: Implemented experimentally
- Date: 2026-08-24

## Summary

EnvVault can attach an existing provider-proxy profile to a sandbox without
changing the provider URL used by the application. A host-side outbound broker
intercepts only configured HTTP or HTTPS destinations, applies the profile's
method and path policy, validates a late-bound `envvault://` credential
reference in the configured bearer field, and injects the upstream credential.
The sandbox receives the non-secret reference, a short-lived proxy capability,
and an ephemeral public CA certificate, never the upstream credential or CA
private key.

The first runtime adapter targets Docker and Node-based coding agents. It sets
standard proxy environment variables, enables Node's environment-proxy support,
and mounts the public CA read-only. This is cooperative interception, not
network enforcement, so the execution continues to report `brokered` rather
than `brokered-enforced`.

## Motivation

The original provider proxy requires an application-specific base URL change.
That works well for SDKs with a supported `base_url` option, including the
current Codex adapter, but does not compose transparently with every tool that
an agent may launch. URL-preserving outbound attachment moves this concern to a
runtime adapter:

```text
sandbox application
  original provider URL
  normal API-key variable = envvault://<credential>
        |
        | HTTP(S)_PROXY + short-lived capability
        v
trusted EnvVault outbound broker
  destination + method + path policy
  ephemeral TLS interception CA
  upstream credential injection
        |
        v
configured provider destination
```

The application may continue to address the original host and initialize its
normal SDK from its normal environment-variable name. The value is the exact
underlying credential reference used by the attached profile, not a raw secret
or an arbitrary placeholder. The SDK sends that reference in its ordinary
bearer field, and the broker resolves it at the last trusted hop.

## Runtime-neutral contracts

The connection layer owns `EgressBroker`, `EgressLease`, `EgressRoute`, and
`EgressClientConfig`:

- a route combines one validated connection policy with non-secret grant
  metadata;
- the broker acquires credentials through `CredentialProvider` and keeps them
  in the trusted process;
- a lease exposes only a proxy endpoint, expiry, redacted client configuration,
  and an idempotent close operation; and
- the client configuration contains a capability-bearing proxy URL, public CA
  certificate, and the non-secret credential references approved for late
  binding.

The sandbox layer owns `EgressAttacher`. A runtime translates the secretless
client configuration into environment, mounts, and cleanup resources. This
keeps Docker-specific trust delivery out of the connection broker and permits
future container, external-sandbox, and microVM adapters.

## Docker attachment

`envvault sandbox run --outbound-profile <profile>` opens one outbound lease
for all selected profiles. The flag is repeatable. `--all` is a CLI selection
shortcut that expands every provider-proxy profile whose project binding
permits the current workspace; it does not bypass policy checks or change the
runtime contract. Docker receives:

- `HTTP_PROXY`, `HTTPS_PROXY`, and their lowercase forms, containing a random
  short-lived proxy capability;
- `NODE_USE_ENV_PROXY=1`;
- `NODE_EXTRA_CA_CERTS=/etc/envvault-outbound/ca.pem`; and
- a read-only mount containing only the ephemeral public CA certificate.

Direct references from `--env` or `--env-file` remain literal only when they
exactly match one of the selected profiles' underlying credentials. An
unmatched direct reference fails before the container is created unless the
operator explicitly selects the raw-materialization compatibility mode.

The example Codex image uses Node 22.22.2. Node's
[built-in environment proxy support](https://nodejs.org/api/http.html#built-in-proxy-support)
is available from Node 22.21.0 and 24.5.0. Other language runtimes may honor the
proxy variables but need their own additive trust-store adapter.

When the invocation also uses EnvVault's existing base-URL gateway, its exact
host and port are added to `NO_PROXY`. This avoids recursively sending one
EnvVault broker through the other.

## Broker behavior

The broker requires HTTP Basic proxy authentication using the random lease
capability. It supports absolute-form HTTP requests and `CONNECT`. Node may use
`CONNECT` for both HTTP and HTTPS origins, so configured destinations are
parsed and authorized inside either kind of tunnel.

For a configured route, the broker:

1. requires the configured authentication field to contain `Bearer` plus the
   route's exact `envvault://<credential>` reference;
2. fixes the upstream scheme, host, port, and base path from trusted policy;
3. rejects encoded, traversal-bearing, disallowed-method, and disallowed-path
   requests;
4. removes hop-by-hop and proxy authentication headers;
5. replaces only the configured authentication header with the upstream bearer
   credential; and
6. refuses to follow upstream redirects while holding that credential.

Missing references, references for another credential, and raw values are
rejected locally and never reach the configured upstream. The broker does not
scan or rewrite request bodies, query strings, or arbitrary header values.

HTTPS routes use a per-lease ECDSA CA. Its private key remains in broker memory;
leaf certificates are minted only for configured destinations and last no
longer than the lease. The broker currently serves HTTP/1.1 inside intercepted
tunnels.

Requests to unconfigured public HTTP or HTTPS destinations may pass through
without credential injection. The broker refuses to tunnel an unconfigured
loopback, private, link-local, or unspecified destination so the host-side
proxy does not become an obvious private-network relay. This check does not
replace runtime egress enforcement: the Docker container still has direct
bridge networking and can bypass the proxy.

## Credential and TLS boundary

The upstream credential may exist only in the credential provider, broker
memory, and authenticated upstream request. It is excluded from sandbox
environment, mounts, command arguments, client configuration, and CLI output.
The `envvault://` reference is an identifier rather than secret material and
may appear in `.env`, process environment, and the outgoing pre-broker request.

The proxy capability is intentionally available in the sandbox environment and
Docker metadata. Anyone able to read it can use the configured broker routes
until lease expiry or cleanup. The CA certificate is public; its private key is
not mounted. The trusted broker can observe allowed request metadata and bodies
because TLS terminates there. TLS certificate pinning and clients that ignore
the mounted CA are incompatible with this prototype.

## Agent authentication composition

Model OAuth remains owned by each coding agent. For Codex,
`--agent-auth native` mounts one explicit EnvVault-managed `CODEX_HOME`; OAuth
login, refresh, and logout remain Codex behavior. Unconfigured public OAuth and
model endpoints are tunneled without EnvVault credential injection.

Provider-specific agent state remains behind agent adapters. Outbound profiles
are independent connection routes for tools the agent invokes. The current
legacy provider-profile translator supports late binding in bearer
authentication only.
Provider-specific API-key headers, signed requests, OAuth token exchange, and
Kaggle/Gemini-specific behavior require separate protocol/provider adapters.

## Failure and cleanup

- An unsupported runtime, invalid profile, project-binding mismatch, duplicate
  route, missing credential, reserved proxy environment variable, or mount
  conflict fails before the container is created.
- A direct reference not covered by a selected outbound profile fails before
  the container is created; a missing or mismatched bearer reference on a
  configured request fails at the broker without contacting the provider.
- A partial broker start revokes every acquired credential lease and clears
  owned credential buffers.
- Container completion, lifecycle failure, cancellation, or interrupt closes
  the broker, active tunnels, credential leases, and temporary CA directory.
- Capabilities and client configuration implement redacted formatting.

## Limitations and next steps

This slice does not provide transparent kernel interception, default-deny
egress, DNS policy, system-wide CA installation, certificate-pinning support,
HTTP/2 interception, configured-destination WebSocket upgrades, byte/connection
limit enforcement, or audit events. It does not claim to be a general TLS
inspection appliance.

The enforcement follow-up should put routing outside the untrusted workload:

1. a Docker sidecar or host service with TPROXY/nftables rules and a private
   network;
2. equivalent routing in a microVM TAP/host-firewall adapter;
3. default-deny DNS and IP egress, including metadata and management networks;
4. tests proving that direct IP, alternate DNS, proxy bypass, and expired
   capabilities fail closed; and
5. metadata-only allow/deny audit events.

Only a runtime that passes those checks may raise the security level to
`brokered-enforced`.

## Verification

Unit tests exercise HTTPS interception, original-URL preservation, proxy
authentication, exact late-bound reference validation, missing and mismatched
reference rejection, method/path rejection, credential replacement, redaction,
and lease shutdown. Opt-in Docker tests exercise Node's real proxy behavior for
HTTP and HTTPS, the mounted CA, an SDK-style credential environment variable,
upstream credential injection, absence of the credential from sandbox metadata,
and container/broker cleanup.
