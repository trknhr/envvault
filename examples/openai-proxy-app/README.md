# OpenAI-Compatible Proxy App Example

This example shows the API proxy flow:

```dotenv
OPENAI_BASE_URL=envvault://openai-proxy/dev/base-url
OPENAI_API_KEY=envvault://openai-proxy/dev/token
```

At runtime, `envvault exec` rewrites those values to a localhost proxy URL and
a local-only bearer token. The real provider API key stays in the OS credential
store and is added only by the proxy when it forwards the request.

Build and initialize EnvVault from the repository root:

```bash
go build -o ./bin/envvault ./cmd/envvault
./bin/envvault init
```

Register a demo provider secret and proxy:

```bash
printf 'sk-local-demo\n' | ./bin/envvault credential set openai-key/dev \
  --value-stdin

./bin/envvault proxy add openai-proxy/dev \
  --credential openai-key/dev \
  --provider generic \
  --target http://127.0.0.1:18080/v1 \
  --allow-path /chat/completions \
  --allow-method POST \
  --project-binding none
```

The command prints a generic `ENVVAULT_PROXY_URL` and `ENVVAULT_PROXY_TOKEN`
snippet. This example uses the same generated references with the variable names
expected by `app.sh`:

```dotenv
OPENAI_BASE_URL=envvault://openai-proxy/dev/base-url
OPENAI_API_KEY=envvault://openai-proxy/dev/token
```

`base-url` is an EnvVault-generated proxy output, not a separate credential to
register.

Start the mock provider in one terminal:

```bash
go run ./examples/openai-proxy-app/mock-provider.go
```

Run the app through EnvVault in another terminal:

```bash
./bin/envvault exec \
  --env OPENAI_BASE_URL=envvault://openai-proxy/dev/base-url \
  --env OPENAI_API_KEY=envvault://openai-proxy/dev/token \
  -- examples/openai-proxy-app/app.sh
```

Or use the checked-in example `.env` file:

```bash
./bin/envvault exec --env-file examples/openai-proxy-app/.env -- \
  examples/openai-proxy-app/app.sh
```

The app should receive a local `pong` response without ever seeing the real
provider key.
