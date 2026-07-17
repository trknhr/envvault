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

The proxy command prints this `.env` snippet:

```dotenv
ENVVAULT_PROXY_URL=envvault://gemini-openai/dev/base-url
ENVVAULT_PROXY_TOKEN=envvault://gemini-openai/dev/token
```

Copy it into the app's `.env` file or pass the same references with
`envvault exec --env`. The example also sets `GEMINI_MODEL=gemini-3.5-flash`.

At runtime, `envvault exec` rewrites `ENVVAULT_PROXY_URL` to a dynamic
localhost proxy URL and `ENVVAULT_PROXY_TOKEN` to a local-only bearer token. The
real Gemini API key stays in the OS credential store and is attached only by the
proxy when forwarding an allowed request.

The EnvVault URI ends with `/base-url` because the proxy automatically
provides a local proxy URL output for the `gemini-openai/dev` profile. It is not
a separate credential to register.

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
printf 'YOUR_GEMINI_API_KEY\n' | ./bin/envvault credential set gemini-api-key \
  --value-stdin
```

Register a proxy for Gemini's OpenAI-compatible API:

```bash
./bin/envvault proxy add gemini-openai/dev \
  --credential gemini-api-key \
  --provider openai-compatible \
  --target https://generativelanguage.googleapis.com/v1beta/openai \
  --allow-path /chat/completions \
  --allow-method POST \
  --project-binding none
```

Copy the generated `ENVVAULT_PROXY_URL` and `ENVVAULT_PROXY_TOKEN` output into
the example `.env` file.

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

This version is different from `examples/gemini-sdk-app`: that example passes
the raw provider key to the official Gemini SDK, while this example gives the
child process only a local proxy token.
