# Gemini AI SDK Proxy App Example

This example calls Gemini through EnvVault's localhost proxy using the AI SDK
OpenAI-compatible provider.

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
  model: gemini.chatModel("gemini-3.5-flash"),
  prompt: "Say pong in one short sentence.",
});
console.log(text);
```

The application keeps only EnvVault proxy references in its `.env` file:

```dotenv
ENVVAULT_PROXY_URL=envvault://gemini-openai/dev/base-url
ENVVAULT_PROXY_TOKEN=envvault://gemini-openai/dev/token
GEMINI_MODEL=gemini-3.5-flash
```

At runtime, `envvault exec` rewrites `ENVVAULT_PROXY_URL` to a dynamic
localhost proxy URL and `ENVVAULT_PROXY_TOKEN` to a local-only bearer token. The
real Gemini API key stays in the OS credential store and is attached only by the
proxy when forwarding an allowed request.

The EnvVault URI still ends with `/base-url` because OpenAI-compatible SDKs
usually call this setting `baseURL`. In EnvVault terms, the resolved value is
the local proxy URL for the `gemini-openai/dev` profile.

Build EnvVault from the repository root:

```bash
go build -o ./bin/envvault ./cmd/envvault
```

Install the example dependencies:

```bash
(cd examples/gemini-ai-sdk-proxy-app && npm install)
```

Store your Gemini API key in the OS credential store:

```bash
printf 'YOUR_GEMINI_API_KEY\n' | ./bin/envvault credential add gemini-api-key \
  --value-stdin
```

Register a proxy profile for Gemini's OpenAI-compatible API:

```bash
./bin/envvault proxy add gemini-openai/dev \
  --credential gemini-api-key \
  --provider openai-compatible \
  --target https://generativelanguage.googleapis.com/v1beta/openai \
  --allow-path /chat/completions \
  --allow-method POST \
  --project-binding none
```

Run the app through EnvVault:

```bash
./bin/envvault exec --env-file examples/gemini-ai-sdk-proxy-app/.env -- \
  npm --prefix examples/gemini-ai-sdk-proxy-app start
```

This version is different from `examples/gemini-sdk-app`: that example injects
the raw provider key for the official Gemini SDK, while this example gives the
child process only a local proxy token.
