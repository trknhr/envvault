# EnvVault

EnvVault is a local-first credential launcher and localhost credential proxy.
Store provider keys in the OS credential store, commit safe
`envvault://` references, and resolve credentials only when starting an app.

Store once. Resolve at launch.

## Quick Start

Install EnvVault from the Homebrew tap after the v0.1.0 release assets are
published:

```bash
brew install trknhr/tap/envvault
```

Register a provider key once. Use the Admin UI for interactive setup:

```bash
envvault admin start
```

The printed localhost URL opens forms for adding credentials and creating proxy
or inject profiles. Stored credential values are not displayed by the UI.

For scripts or repeatable tests, use the equivalent CLI path:

```bash
printf 'YOUR_GEMINI_API_KEY\n' | envvault credential add gemini-api-key \
  --value-stdin
```

Create a proxy profile:

```bash
envvault proxy add gemini-openai/dev \
  --credential gemini-api-key \
  --provider openai-compatible \
  --target https://generativelanguage.googleapis.com/v1beta/openai \
  --allow-path /chat/completions \
  --allow-method POST \
  --project-binding none
```

The command prints a `.env` snippet. Copy it into the app's `.env` file or pass
the same references with `envvault exec --env`:

```dotenv
ENVVAULT_PROXY_URL=envvault://gemini-openai/dev/base-url
ENVVAULT_PROXY_TOKEN=envvault://gemini-openai/dev/token
```

Launch the app through EnvVault:

```bash
envvault exec \
  --env ENVVAULT_PROXY_URL=envvault://gemini-openai/dev/base-url \
  --env ENVVAULT_PROXY_TOKEN=envvault://gemini-openai/dev/token \
  -- npm start

envvault exec --env-file .env -- npm start
```

## Credential flows

- **Proxy**: use the generated `envvault://profile/base-url` and `envvault://profile/token` references when an app accepts a custom endpoint and bearer token.
- **Raw inject fallback**: use `envvault://profile/value` when an SDK or tool requires the raw credential.
- **Local policy**: store non-secret profile policy locally and keep provider credentials in the OS credential store.

## Agent Skill

Install the EnvVault skill with the `skills` CLI:

```bash
npx skills add trknhr/envvault --skill envvault
```

From a local checkout:

```bash
npx skills add . --skill envvault
```

Use the `skills` CLI options to choose global/project scope or a specific
agent, for example `-g` for global installation or `-a <agent>`.
Restart your agent after installing or updating skills.

## Gemini AI SDK proxy

The [Gemini AI SDK proxy example](/examples/gemini-ai-sdk-proxy-app) shows the
main v0.1 workflow: a provider key stays in the OS credential store while the
app receives only a localhost proxy URL and local token.
