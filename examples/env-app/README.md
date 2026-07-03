# Env App Example

This example shows the default direct credential flow for tools that expect a
normal environment variable:

```dotenv
DATABASE_URL=envvault://database/dev
```

Build and initialize EnvVault from the repository root:

```bash
go build -o ./bin/envvault ./cmd/envvault
./bin/envvault init
```

Register a local credential:

```bash
printf 'postgres://user:pass@127.0.0.1:5432/app\n' | ./bin/envvault credential add database/dev \
  --value-stdin
```

Run the app through EnvVault:

```bash
./bin/envvault exec --env DATABASE_URL=envvault://database/dev -- \
  examples/env-app/app.sh
```

Or use the checked-in example `.env` file:

```bash
./bin/envvault exec --env-file examples/env-app/.env -- \
  examples/env-app/app.sh
```

The app receives `DATABASE_URL` as a normal environment value. Use proxy mode
only when the API or SDK supports a custom base URL and bearer token.
