# Examples

EnvVault includes runnable examples for raw-injection and proxy workflows.

## Inject examples

- [Gemini SDK inject app](https://github.com/trknhr/envvault/blob/main/examples/gemini-sdk-app/README.md)
- [Raw inject app](https://github.com/trknhr/envvault/blob/main/examples/inject-app/README.md)

Use these for the default compatibility path. The app receives the resolved
credential as a normal environment variable at process launch.

```dotenv
GEMINI_API_KEY=envvault://gemini/dev/value
```

## Advanced proxy examples

- [Gemini AI SDK proxy app](/examples/gemini-ai-sdk-proxy-app)
- [OpenAI-compatible proxy app](/examples/openai-proxy-app)

Use these when an SDK accepts a custom base URL and bearer token, and you do not
want to pass the real provider key to the child process.

You can register the credential and proxy profile from the Admin UI, or use the
CLI commands in each example for repeatable local testing. A proxy profile
creates these references automatically; copy the generated snippet into the
app's `.env` file or pass the references directly with `envvault exec --env`.

```dotenv
ENVVAULT_PROXY_URL=envvault://gemini-openai/dev/base-url
ENVVAULT_PROXY_TOKEN=envvault://gemini-openai/dev/token
```
