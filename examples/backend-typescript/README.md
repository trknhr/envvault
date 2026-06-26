# TypeScript Backend Example

This example shows the HTTP surface a TypeScript or JavaScript backend needs in order to accept EnvVault process JWTs and browser session bootstrap requests.

The example uses only Node built-in modules so the control flow is visible:

- `GET /documents/read` checks the Authorization header, validates EnvVault claims, and requires a read scope.
- `POST /auth/envvault/browser-sessions` validates a browser bootstrap credential, enforces replay protection, and returns a fixed complete URL.
- `GET /auth/envvault/complete` consumes a one-time code and redirects to a fixed post-login URL.

The example validates the `envvault_resource`, `envvault_purpose`, and `scope` claims before returning application data or browser session state.

For production, replace the intentionally small verifier in `server.mjs` with a maintained JWT/JWKS library and a durable replay/code store.

```bash
JWKS_FILE=./envvault-jwks.json \
ISSUER=envvault-local:test-install \
RESOURCE=http://127.0.0.1:8080 \
node examples/backend-typescript/server.mjs
```
