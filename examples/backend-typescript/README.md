# TypeScript Backend Example

This example shows the HTTP surface a TypeScript or JavaScript backend needs in order to accept Credlease process JWTs and browser session bootstrap requests.

The example uses only Node built-in modules so the control flow is visible:

- `GET /documents/read` checks the Authorization header, validates Credlease claims, and requires a read scope.
- `POST /auth/credlease/browser-sessions` validates a browser bootstrap credential, enforces replay protection, and returns a fixed complete URL.
- `GET /auth/credlease/complete` consumes a one-time code and redirects to a fixed post-login URL.

The example validates the `credlease_resource`, `credlease_purpose`, and `scope` claims before returning application data or browser session state.

For production, replace the intentionally small verifier in `server.mjs` with a maintained JWT/JWKS library and a durable replay/code store.

```bash
JWKS_FILE=./credlease-jwks.json \
ISSUER=credlease-local:test-install \
RESOURCE=http://127.0.0.1:8080 \
node examples/backend-typescript/server.mjs
```
