# Examples

EnvVault includes runnable examples for proxy and raw-injection workflows.

## Proxy examples

- [Gemini AI SDK proxy app](/examples/gemini-ai-sdk-proxy-app)
- [OpenAI-compatible proxy app](/examples/openai-proxy-app)

Use these when an SDK accepts a custom base URL and bearer token.

You can register the credential and profile from the Admin UI, or use the CLI
commands in each example for repeatable local testing. A proxy profile creates
these references automatically; copy the generated snippet into the app's
`.env` file or pass the references directly with `envvault exec --env`.

```dotenv
ENVVAULT_PROXY_URL=envvault://gemini-openai/dev/base-url
ENVVAULT_PROXY_TOKEN=envvault://gemini-openai/dev/token
```

## Inject examples

- [Gemini SDK inject app](https://github.com/trknhr/envvault/blob/feat/local-mvp/examples/gemini-sdk-app/README.md)
- [Raw inject app](https://github.com/trknhr/envvault/blob/feat/local-mvp/examples/inject-app/README.md)

Use raw injection only when proxying is not possible.

```dotenv
GEMINI_API_KEY=envvault://gemini/dev/value
```
