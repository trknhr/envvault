# EnvVault

EnvVault is a lightweight local secret launcher. Store provider keys in the OS
credential store, commit safe `envvault://` references, and resolve credentials
only when starting an app.

Store once. Resolve at launch.

## Quick Start

Install EnvVault from the Homebrew tap:

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

Create an inject profile:

```bash
envvault inject add gemini/dev \
  --credential gemini-api-key \
  --project-binding none
```

Use a repository-safe reference in the app's `.env` file or pass the same
reference with `envvault exec --env`:

```dotenv
GEMINI_API_KEY=envvault://gemini/dev/value
```

Launch the app through EnvVault:

```bash
envvault exec \
  --env GEMINI_API_KEY=envvault://gemini/dev/value \
  -- npm start

envvault exec --env-file .env -- npm start
```

## Credential flows

- **Inject**: use `envvault://profile/value` for the default compatibility path.
- **Proxy**: use the generated `envvault://profile/base-url` and `envvault://profile/token` references when an app accepts a custom endpoint and bearer token and you do not want to pass the real provider key to the child process.
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

## Advanced API proxy

The [Gemini AI SDK proxy example](/examples/gemini-ai-sdk-proxy-app) shows the
optional proxy workflow: a provider key stays in the OS credential store while
the app receives only a localhost proxy URL and local token.
