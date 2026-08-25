# Gemini AI SDK Outbound Sandbox App Example

This example calls Gemini at its original public URL while EnvVault keeps the
real API key outside the Docker sandbox. It uses the same environment-variable
name and SDK configuration that an application can use in production.

The checked-in `.env` contains only a credential reference:

```dotenv
GEMINI_API_KEY=envvault://gemini-api-key
GEMINI_MODEL=gemini-3.5-flash
```

The app loads that file itself with Node's built-in `loadEnvFile`, then creates
the AI SDK provider normally:

```js
const gemini = createOpenAICompatible({
  baseURL: "https://generativelanguage.googleapis.com/v1beta/openai",
  name: "gemini",
  apiKey: process.env.GEMINI_API_KEY,
});
```

Inside the sandbox, `GEMINI_API_KEY` is still the literal
`envvault://gemini-api-key` reference. The SDK sends it in its ordinary bearer
field. EnvVault's outbound broker accepts that exact reference for the attached
profile and substitutes the real key only after destination, method, and path
checks. The app does not use an EnvVault-specific base URL or tool call.

## Set Up EnvVault

Build the CLI and the example Codex image from the repository root:

```bash
go build -o ./bin/envvault ./cmd/envvault

docker build \
  --tag envvault-codex:local \
  examples/codex-sandbox
```

Store the Gemini API key without putting it on the command line:

```bash
./bin/envvault credential set gemini-api-key
```

Register a profile for Gemini's OpenAI-compatible endpoint:

```bash
./bin/envvault proxy add gemini-openai/dev \
  --credential gemini-api-key \
  --provider openai-compatible \
  --target https://generativelanguage.googleapis.com/v1beta/openai \
  --allow-path /chat/completions \
  --allow-method POST \
  --project-binding none
```

The `.env` reference names the underlying credential (`gemini-api-key`), not
the outbound profile (`gemini-openai/dev`).

## Run The App

Install dependencies on the host so they are available through the workspace
mount:

```bash
(cd examples/gemini-ai-sdk-outbound-app && npm install)
```

Run the app in Docker with the original-URL outbound profile attached:

```bash
./bin/envvault sandbox run \
  --outbound-profile gemini-openai/dev \
  --runtime docker \
  --image envvault-codex:local \
  -- npm --prefix examples/gemini-ai-sdk-outbound-app start
```

No `--env-file` flag is needed because the app reads its mounted `.env` file.
If the app instead expects process environment, add
`--env-file examples/gemini-ai-sdk-outbound-app/.env`; EnvVault preserves the
matching reference rather than materializing it.

Pass a different prompt after `--` to the npm script:

```bash
./bin/envvault sandbox run \
  --outbound-profile gemini-openai/dev \
  --runtime docker \
  --image envvault-codex:local \
  -- npm --prefix examples/gemini-ai-sdk-outbound-app start -- \
  "Review this late-binding design in one sentence."
```

## Use It From Codex

Attach the same outbound profile independently of Codex's model login:

```bash
./bin/envvault sandbox run -it \
  --agent-auth native \
  --agent-auth-profile personal \
  --outbound-profile gemini-openai/dev \
  --runtime docker \
  --image envvault-codex:local \
  -- codex
```

For repeated local use, the
[documented zsh wrapper](../../docs/sandbox.md#daily-codex-wrapper-zsh) leaves
outbound profiles unset by default. Attach Gemini only for sessions that need
it:

```bash
evcodex -o gemini-openai/dev
```

The outbound attachment is cooperative in this prototype. A client must honor
the injected proxy and CA settings, and direct Docker bridge egress is not yet
blocked. Missing or mismatched credential references are rejected locally and
never sent to the configured provider.
