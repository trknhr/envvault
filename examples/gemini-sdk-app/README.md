# Gemini SDK App Example

This example calls Gemini with the official JavaScript SDK:

```js
import { GoogleGenAI } from "@google/genai";

const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });
const interaction = await ai.interactions.create({
  model: "gemini-3.5-flash",
  input: "Say pong in one short sentence.",
});
console.log(interaction.output_text);
```

The application keeps only an EnvVault reference in its `.env` file:

```dotenv
GEMINI_API_KEY=envvault://gemini/dev
GEMINI_MODEL=gemini-3.5-flash
```

This is the default direct credential flow. It is useful for SDKs that expect
the real provider key in code or in an environment variable. Unlike the
localhost proxy flow, the child process receives the real Gemini API key.

Build EnvVault from the repository root:

```bash
go build -o ./bin/envvault ./cmd/envvault
```

Install the example dependency:

```bash
(cd examples/gemini-sdk-app && npm install)
```

Store your Gemini API key in the OS credential store:

```bash
printf 'YOUR_GEMINI_API_KEY\n' | ./bin/envvault credential add gemini/dev \
  --value-stdin
```

Run the app through EnvVault:

```bash
./bin/envvault exec \
  --env GEMINI_API_KEY=envvault://gemini/dev \
  --env GEMINI_MODEL=gemini-3.5-flash \
  -- npm --prefix examples/gemini-sdk-app start
```

Or use the checked-in example `.env` file:

```bash
./bin/envvault exec --env-file examples/gemini-sdk-app/.env -- \
  npm --prefix examples/gemini-sdk-app start
```

If you already added `gemini/dev` in the Admin UI, you can skip the
`credential add` command.
