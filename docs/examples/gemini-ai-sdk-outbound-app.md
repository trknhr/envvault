# Gemini AI SDK Outbound Sandbox App Example

This example keeps Gemini's original public URL and the application's normal
`GEMINI_API_KEY` variable while EnvVault keeps the real API key outside the
Docker sandbox.

The app loads its checked-in `.env` file itself:

```dotenv
GEMINI_API_KEY=envvault://gemini-api-key
GEMINI_MODEL=gemini-3.5-flash
```

It initializes the AI SDK normally:

```js
const gemini = createOpenAICompatible({
  baseURL: "https://generativelanguage.googleapis.com/v1beta/openai",
  name: "gemini",
  apiKey: process.env.GEMINI_API_KEY,
});
```

The SDK sends the literal reference in its bearer field. The outbound broker
requires that exact reference, applies the profile's destination, method, and
path policy, then substitutes the real credential at egress. It does not
rewrite the provider URL, `.env` file, request body, or arbitrary headers.

## Set Up The Credential And Profile

```bash
./bin/envvault credential set gemini-api-key

./bin/envvault proxy add gemini-openai/dev \
  --credential gemini-api-key \
  --provider openai-compatible \
  --target https://generativelanguage.googleapis.com/v1beta/openai \
  --allow-path /chat/completions \
  --allow-method POST \
  --project-binding none
```

The reference names the underlying credential (`gemini-api-key`), while
`--outbound-profile` selects the provider profile (`gemini-openai/dev`).

## Run The Example

Build the image and install dependencies once:

```bash
docker build --tag envvault-codex:local examples/codex-sandbox
(cd examples/gemini-ai-sdk-outbound-app && npm install)
```

Run the app without changing its provider URL or passing `.env` through
EnvVault:

```bash
./bin/envvault sandbox run \
  --outbound-profile gemini-openai/dev \
  --runtime docker \
  --image envvault-codex:local \
  -- npm --prefix examples/gemini-ai-sdk-outbound-app start
```

The application reads the mounted project `.env` directly. Applications that
expect process environment can add
`--env-file examples/gemini-ai-sdk-outbound-app/.env`; the matching reference
is still preserved rather than materialized.

See the
[example README](https://github.com/trknhr/envvault/blob/main/examples/gemini-ai-sdk-outbound-app/README.md)
for the interactive Codex command and a custom-prompt example. For repeated
sessions, the [daily Codex wrapper](/sandbox#daily-codex-wrapper-zsh) attaches
Gemini with `evcodex -o gemini-openai/dev` instead of fixing that profile for
every sandbox.

This prototype reports `brokered`, not `brokered-enforced`: clients can bypass
the cooperative proxy through direct Docker bridge egress.
