# Examples

EnvVault includes runnable examples for direct credential and proxy workflows.

## Direct Credential Examples

- [Gemini SDK app](https://github.com/trknhr/envvault/blob/main/examples/gemini-sdk-app/README.md)
- [Shell env app](https://github.com/trknhr/envvault/blob/main/examples/env-app/README.md)

Use these for the default compatibility path. The app receives the resolved
credential as a normal environment variable at process launch.

```dotenv
GEMINI_API_KEY=envvault://gemini/dev
```

## Advanced Proxy Examples

- [Gemini AI SDK proxy app](/examples/gemini-ai-sdk-proxy-app)
- [OpenAI-compatible proxy app](/examples/openai-proxy-app)

Use these when an SDK accepts a custom base URL and bearer token, and you do not
want to pass the real provider key to the child process.

You can register the credential and proxy from the Admin UI, or use the CLI
commands in each example for repeatable local testing. A proxy creates these
references automatically; copy the generated snippet into the app's `.env` file
or pass the references directly with `envvault exec --env`.

```dotenv
ENVVAULT_PROXY_URL=envvault://gemini-openai/dev/base-url
ENVVAULT_PROXY_TOKEN=envvault://gemini-openai/dev/token
```

## Original-URL Outbound Sandbox Example

- [Gemini AI SDK outbound sandbox app](/examples/gemini-ai-sdk-outbound-app)

Use this when an SDK should retain its production provider URL and normal
API-key variable while the real credential remains outside the sandbox:

```dotenv
GEMINI_API_KEY=envvault://gemini-api-key
```

The app loads this project `.env` itself. With
`--outbound-profile gemini-openai/dev`, the broker requires the exact reference
in the SDK's bearer field and substitutes the real key only at egress.

## Run a Proxy Example in Docker

After installing the Gemini example dependencies, the same checked-in `.env`
references can be used in the experimental Docker sandbox:

```bash
./bin/envvault sandbox run \
  --runtime docker \
  --image node:22 \
  --env-file examples/gemini-ai-sdk-proxy-app/.env \
  -- npm --prefix examples/gemini-ai-sdk-proxy-app start
```

The repository is mounted at `/workspace`. The container receives the gateway
URL and temporary capability, not the Gemini API key. This currently reports
`brokered`, because the Docker bridge still permits direct egress.
