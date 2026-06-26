# OpenAI-Compatible Proxy App Example

This example shows the third-party API flow:

```dotenv
OPENAI_BASE_URL=envvault://openai/dev/base-url
OPENAI_API_KEY=envvault://openai/dev/token
```

At runtime, `envvault exec` rewrites those values to a localhost proxy URL and
a local-only bearer token. The real provider API key stays in the OS credential
store and is injected only by the proxy when it forwards the request.

Build and initialize EnvVault from the repository root:

```bash
go build -o ./bin/envvault ./cmd/envvault
./bin/envvault init
```

Register a demo provider secret and proxy profile:

```bash
printf 'sk-local-demo\n' | ./bin/envvault credential add openai-key/dev \
  --value-stdin

./bin/envvault proxy add openai/dev \
  --credential openai-key/dev \
  --provider generic \
  --target http://127.0.0.1:18080/v1 \
  --allow-path /chat/completions \
  --allow-method POST \
  --project-binding none
```

Start the mock provider in one terminal:

```bash
go run ./examples/openai-proxy-app/mock-provider.go
```

Run the app through EnvVault in another terminal:

```bash
./bin/envvault exec --env-file examples/openai-proxy-app/.env -- \
  examples/openai-proxy-app/app.sh
```

The app should receive a local `pong` response without ever seeing the real
provider key.
