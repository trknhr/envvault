# Local MVP App Example

This example is a small app that reads `BACKEND_A_TOKEN` from its environment
and calls the Go sample backend.

The `.env` file contains only EnvVault references and non-secret local config:

```dotenv
BACKEND_A_TOKEN=envvault://backend-a/dev
API_BASE_URL=http://127.0.0.1:8080
```

Start the sample backend from the repository root:

```bash
mkdir -p tmp
./bin/envvault jwks export --output ./tmp/envvault-jwks.json
ISSUER="$(./bin/envvault issuer show)"

go run ./examples/backend-go/cmd/backend \
  --jwks ./tmp/envvault-jwks.json \
  --issuer "$ISSUER" \
  --resource http://127.0.0.1:8080 \
  --complete-url http://127.0.0.1:8080/auth/envvault/complete \
  --post-login-url http://127.0.0.1:8080/
```

In another terminal, run this app through EnvVault:

```bash
./bin/envvault exec --env-file examples/local-mvp-app/.env -- \
  examples/local-mvp-app/app.sh
```

The backend should return an `ok: true` JSON response.
