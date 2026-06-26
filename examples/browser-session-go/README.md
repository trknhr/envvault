# Browser Session Go Example

This example shows how a Go backend can wire `pkg/browsersession` directly when it only needs the browser session protocol.

It uses:

- `pkg/verifier` to validate the bootstrap credential from the Authorization header.
- `pkg/browsersession` middleware for exchange and complete endpoints.
- the SQLite replay/code store for local durable single-use semantics.

```bash
go run ./examples/browser-session-go/cmd/server \
  --jwks ./envvault-jwks.json \
  --issuer envvault-local:test-install \
  --resource http://127.0.0.1:8080 \
  --sqlite ./browser-session.sqlite
```
