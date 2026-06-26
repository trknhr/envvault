# Raw Inject App Example

This example shows the fallback flow for tools that must receive a raw
credential value:

```dotenv
DATABASE_URL=envvault://database/dev/value
```

Build and initialize EnvVault from the repository root:

```bash
go build -o ./bin/envvault ./cmd/envvault
./bin/envvault init
```

Register a local credential and inject profile:

```bash
printf 'postgres://user:pass@127.0.0.1:5432/app\n' | ./bin/envvault credential add database-url/dev \
  --value-stdin

./bin/envvault inject add database/dev \
  --credential database-url/dev \
  --project-binding none
```

Run the app through EnvVault:

```bash
./bin/envvault exec --env-file examples/inject-app/.env -- \
  examples/inject-app/app.sh
```

The app receives `DATABASE_URL` as a raw environment value. Prefer a proxy
profile when the API or SDK supports a custom base URL and bearer token.
