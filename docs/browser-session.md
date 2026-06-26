# Browser Session Protocol

The browser-session protocol lets a backend create its own web session without putting a EnvVault JWT in a browser URL. EnvVault sends the bootstrap JWT to the backend exchange endpoint in the Authorization header, then opens a fixed complete URL containing only a short-lived one-time code.

## Exchange Endpoint

The backend receives:

```text
POST /auth/envvault/browser-sessions
Authorization: <bootstrap credential>
```

Exchange endpoint requirements:

- Accept the bootstrap credential only from the Authorization header.
- Validate signature, issuer, expiry, scope, resource, and purpose.
- Atomically insert `envvault_session_id` into a replay cache.
- Reject a reused session ID.
- Generate the one-time code with a cryptographically secure random source.
- Keep the code raw value out of logs.
- Limit the code to one use and a maximum lifetime of 30 seconds.
- Return only the fixed complete URL.
- Set `Cache-Control: no-store`.

## Complete Endpoint

The browser follows the complete endpoint:

```text
GET /auth/envvault/complete?code=<opaque>
```

Complete endpoint requirements:

- Atomically consume the code.
- Return the same generic error for expired, unknown, and already-used codes.
- Set the session cookie.
- Redirect with `303 See Other` to the profile's fixed post-login URL.
- Do not copy the code into the redirect target.
- Set `Referrer-Policy: no-referrer` and `Cache-Control: no-store`.

## Cookie and Redirect Rules

Session cookies must be `HttpOnly`. HTTPS deployments must also set `Secure`. `SameSite=Lax` or stricter is required, and cookie path/domain should be as narrow as the application allows.

The CLI must not provide arbitrary redirect targets. Backend configuration and the EnvVault profile both fix the complete URL and post-login URL. Host mismatches are rejected before the browser is launched.

## Store Implementations

`pkg/browsersession` provides in-memory replay and login-code stores for examples and tests. It also provides a SQLite-backed store for local practical use. The SQLite store persists replay entries and pending login codes across process restarts, consumes codes with a single atomic delete, and stores only a SHA-256 hash of each raw login code.
