# Gemini AI SDK Proxy App Example

This example calls Gemini through EnvVault's localhost proxy using the AI SDK
OpenAI-compatible provider.

The proxy profile command prints this `.env` snippet:

```dotenv
ENVVAULT_PROXY_URL=envvault://gemini-openai/dev/base-url
ENVVAULT_PROXY_TOKEN=envvault://gemini-openai/dev/token
```

Copy it into the app's `.env` file or pass the same references with
`envvault exec --env`. The example also sets `GEMINI_MODEL=gemini-3.5-flash`.

At runtime, `envvault exec` rewrites `ENVVAULT_PROXY_URL` to a dynamic localhost
proxy URL and `ENVVAULT_PROXY_TOKEN` to a local-only bearer token. The real
Gemini API key stays in the OS credential store and is attached only by the
proxy when forwarding an allowed request.

The app uses the AI SDK like this:

```js
import { createOpenAICompatible } from "@ai-sdk/openai-compatible";
import { generateText } from "ai";

const gemini = createOpenAICompatible({
  baseURL: process.env.ENVVAULT_PROXY_URL,
  name: "gemini",
  apiKey: process.env.ENVVAULT_PROXY_TOKEN,
});

const { text } = await generateText({
  model: gemini.chatModel(process.env.GEMINI_MODEL ?? "gemini-3.5-flash"),
  prompt: "Say pong in one short sentence.",
});
console.log(text);
```

## Register The Credential And Proxy

For interactive setup, start the Admin UI and add a credential named
`gemini-api-key`, then create a proxy profile named `gemini-openai/dev` with the
settings below.

```bash
envvault admin start
```

For repeatable local testing, use the equivalent CLI commands:

```bash
printf 'YOUR_GEMINI_API_KEY\n' | ./bin/envvault credential add gemini-api-key \
  --value-stdin

./bin/envvault proxy add gemini-openai/dev \
  --credential gemini-api-key \
  --provider openai-compatible \
  --target https://generativelanguage.googleapis.com/v1beta/openai \
  --allow-path /chat/completions \
  --allow-method POST \
  --project-binding none
```

The command prints the `ENVVAULT_PROXY_URL` and `ENVVAULT_PROXY_TOKEN`
references. `base-url` is an EnvVault-generated proxy output, not a separate
credential to register.

## Run The Example

Build EnvVault and install the example dependencies:

```bash
go build -o ./bin/envvault ./cmd/envvault
(cd examples/gemini-ai-sdk-proxy-app && npm install)
```

Run the app through EnvVault:

```bash
./bin/envvault exec \
  --env ENVVAULT_PROXY_URL=envvault://gemini-openai/dev/base-url \
  --env ENVVAULT_PROXY_TOKEN=envvault://gemini-openai/dev/token \
  --env GEMINI_MODEL=gemini-3.5-flash \
  -- npm --prefix examples/gemini-ai-sdk-proxy-app start
```

Or use the checked-in example `.env` file:

```bash
./bin/envvault exec --env-file examples/gemini-ai-sdk-proxy-app/.env -- \
  npm --prefix examples/gemini-ai-sdk-proxy-app start
```

This differs from the Gemini SDK inject example: that flow passes the raw
provider key to the child process, while this flow gives the child process only
a localhost proxy URL and local token.
