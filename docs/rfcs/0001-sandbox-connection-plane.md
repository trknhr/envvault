# RFC 0001: Sandbox connection plane

- Status: Draft
- Date: 2026-08-03

## Summary

EnvVault will evolve from a local secret launcher into a local-first connection
broker for commands running in existing sandbox runtimes. In brokered modes,
the application or AI agent receives a short-lived connection capability, not
the upstream credential. A trusted gateway outside the sandbox authenticates
approved connections with credentials obtained from a credential provider.

This RFC defines the connection domain and its phased integration. The initial
EVS-001 slice added only the model; later explicitly selected slices add the
compatibility adapter, orchestration, and experimental runtime without changing
the stored configuration format or the existing `envvault exec` contract.

## Product boundary

EnvVault will provide three pieces:

1. thin adapters for existing sandbox runtimes;
2. a trusted, protocol-aware connection gateway outside the sandbox; and
3. policy for destinations, protocols, credential sources, lifetimes, and
   resource limits.

EnvVault will not implement a hypervisor, container engine, generic DLP system,
SQL authorization firewall, dynamic-secret engine, or production PaaS.

NVIDIA OpenShell is a reference product for gateway, provider, and policy
design. OpenSandbox is a separate project and a possible future runtime adapter;
this RFC does not integrate either one.

## Compatibility

Existing behavior remains unchanged:

- `envvault exec` may materialize direct `envvault://<credential>` references.
- home-file resolution remains materialized credential delivery.
- existing provider proxies remain HTTP-only localhost servers.
- `profile.Profile`, `issuer.Grant`, and `internal/runtime/talos` retain their
  current names and responsibilities.

The compatibility layer translates provider-proxy profiles to HTTP connection
policies without changing the stored profile schema or activating the new
runtime. It preserves the target base path and provider strategy. Project
binding remains on the legacy profile and must be checked before a translated
policy is used.

The translator rejects target URL userinfo, fixed query strings, fragments, and
encoded base paths even though legacy validation accepted them. Those values
cannot be represented unambiguously by the typed policy and therefore fail
closed. Allowed methods and credential references must also round-trip without
normalization or reserved-suffix ambiguity. A zero policy connection or byte
limit means that the legacy source did not specify that limit; grant issuance
must resolve the connection limit to a positive value before creating a
capability.

## Implementation status

The first compatibility slice now includes the provider-proxy translator, an
HTTP `ProtocolAdapter`, a static keyring credential provider, runtime-neutral
sandbox lifecycle orchestration, and an experimental Docker runtime exposed as
`envvault sandbox run`. Existing `envvault exec` and stored profile formats
remain compatible.

The Docker runtime reports `brokered`. It deliberately does not claim
`brokered-enforced`: the application uses Docker bridge networking with direct
egress, and the container-reachable host gateway is protected by a temporary
capability rather than network allowlisting. Enforced topology remains subject
to a separate egress RFC and acceptance tests.

EVS-006 adds a versioned stdio plugin contract for existing agent-sandbox
control planes. That contract makes the external sandbox platform the owner of
runtime and network enforcement while EnvVault owns connection leases and raw
credential handling. See
[RFC 0002](./0002-external-sandbox-plugin.md).

The next experimental slice adds a runtime-neutral outbound broker and Docker
egress attachment that preserve original provider URLs through an authenticated
HTTP proxy and ephemeral CA. It remains cooperative `brokered` delivery; direct
egress is not blocked. See
[RFC 0003](./0003-url-preserving-outbound-broker.md).

## Trust boundary

The EnvVault CLI, credential provider, connection gateway, and policy engine
are trusted. The sandbox, application, AI agent, generated code, and installed
packages are untrusted. A raw credential may exist in the credential provider,
trusted gateway memory, and the authenticated upstream request. It must not be
placed in the sandbox environment, filesystem, command line, image, grant,
audit record, or error output when delivery is `proxy`.

A localhost address inside a container or VM refers to the sandbox, not the
host. A future runtime must therefore provide either a secretless local relay or
a private route to the external gateway. Proxy environment variables alone are
not an egress security boundary.

## Authentication dimensions

Credential delivery and credential issuance are independent:

- `delivery: proxy` keeps credential material outside the sandbox.
- `delivery: materialize` places credential material in the sandbox and must be
  an explicit compatibility opt-in for future sandbox commands.
- `issuance: static` reads an existing credential.
- `issuance: dynamic` requests a bounded credential lease from a provider.

For example, a gateway can proxy a PostgreSQL connection using a dynamic
30-minute OpenBao credential. That is proxy delivery with dynamic issuance.

The first implementation target is proxy delivery backed by a static keyring
credential.

## Domain model

`connection.Policy` is the long-lived, repository-safe declaration. It contains
a fixed destination, a typed protocol policy, authentication metadata, limits,
and metadata-only audit policy.

`connection.ProtocolSpec` is a discriminated union. Exactly one of its typed
protocol policies must be set and it must match `ProtocolSpec.Type`. Core policy
does not use `map[string]any` for protocol settings.

`connection.Grant` is non-secret metadata for one short-lived connection
capability. The unpredictable opaque capability is stored and compared by the
runtime session layer rather than embedded in this model. It is bound to a
session, subject, policy revision, protocol, destination, expiry, and limits.

`connection.Session` contains non-secret runtime counters and revocation state.
Credential material is acquired by a protocol adapter only when needed.

The credential-provider interface exposes material only through a callback so
the domain model has no exported raw-secret field. Implementations must redact
formatting and errors and clear owned buffers after use.

## Protocols

HTTP is the first adapter. The existing provider proxy is the compatibility
baseline: fixed HTTPS or loopback-HTTP destination, bearer injection, exact
allowed methods and paths, bounded local token lifetime, project binding, and
no secret logging.

PostgreSQL is the first planned non-HTTP adapter. It will terminate the client
protocol, bind the requested database and upstream user to policy, verify
upstream TLS, and perform upstream authentication. PostgreSQL authorization
remains the responsibility of database roles, schema privileges, RLS, and
database-side limits. SQL text will not be used as the primary authorization
boundary.

MySQL, Redis, SSH, and generic TCP have typed placeholders so their future RFCs
can extend the union without adding fields to `profile.Profile`. Generic TCP
cannot perform arbitrary application credential injection; proxy delivery is
rejected until an explicit protocol-specific authentication strategy such as
mTLS is designed.

## Security levels

Future sandbox executions will report one of these levels:

- `materialized-static`: a fixed raw credential is placed in the sandbox;
- `materialized-leased`: a short-lived raw credential is placed in the sandbox;
- `brokered`: no raw credential is delivered, but direct egress is not fully
  blocked; or
- `brokered-enforced`: no raw credential is delivered and default-deny egress is
  enforced outside the sandbox.

A runtime must not claim `brokered-enforced` until integration tests demonstrate
that direct IP and DNS access, alternate DNS, metadata endpoints, management
interfaces, cross-session capabilities, and expired capabilities fail closed.

## Audit

Audit remains metadata-only. Allowed fields include session and sandbox IDs,
runtime, policy name and revision, protocol, destination, security level,
timestamps, result, byte counters, connection count, and stable deny codes.
Credentials, capabilities, proxy tokens, authorization headers, HTTP bodies,
SQL text, SSH payloads, Redis arguments, and full environments are excluded.

## Delivery plan

1. Add this RFC and the typed connection model with no behavior change.
2. Translate existing provider-proxy profiles into HTTP policies.
3. wrap the existing provider proxy as a protocol adapter.
4. add a fake sandbox runtime and lifecycle orchestration tests.
5. add an experimental Docker runtime.
6. add an external agent-sandbox plugin contract without raw credential
   delivery.
7. integrate one existing sandbox platform and test composed egress policy.
8. specify and implement a PostgreSQL adapter.
9. expand one runtime, protocol, or credential provider at a time.

Remote gateways are deferred. Their node identity will be separate from a
per-session connection grant. A future RFC will specify SSH-assisted initial
enrollment, mTLS authentication, certificate rotation, and revocation.

## Decision

Deliver the work in the numbered slices above. EVS-001 remains a domain-only,
no-behavior-change boundary. `envvault sandbox run` remains a reference runtime;
existing sandbox products should integrate through the external plugin
contract. OpenShell-specific packaging, PostgreSQL, configuration migration,
Talos integration, and enforced egress remain separate slices.
