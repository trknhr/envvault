# EnvVault

Keep real secrets out of project `.env` files and coding-agent prompts.

EnvVault replaces plaintext `.env` secrets with repository-safe `envvault://`
references. At runtime, it resolves credentials from the OS credential store or
starts a localhost proxy that gives the app a local URL and local proxy token.

## Quick Start

Install EnvVault from the Homebrew tap:

```bash
brew install trknhr/tap/envvault
```

Register a credential once. Use the Admin UI for interactive setup:

```bash
envvault admin start
```

The printed localhost URL opens forms for adding credentials and creating
optional proxies. Stored credential values are not displayed by the UI.

For scripts or repeatable tests, use the equivalent CLI path:

```bash
printf 'secret-value\n' | envvault credential add app/dev \
  --value-stdin
```

Use a repository-safe reference in the app's `.env` file or pass the same
reference with `envvault exec --env`:

```dotenv
APP_SECRET=envvault://app/dev
```

Launch the app through EnvVault:

```bash
envvault exec \
  --env APP_SECRET=envvault://app/dev \
  -- npm start

envvault exec --env-file .env -- npm start
```

## Credential Flows

- **Direct credential**: use `envvault://<credential>` for the default local
  development path. The child process receives the real value in its
  environment.
- **Proxy**: use generated `envvault://<proxy>/base-url` and
  `envvault://<proxy>/token` references when an app accepts a custom endpoint
  and bearer token.
- **Local state**: store only credential names and proxy policy in config; store
  real credential values in the OS credential store.

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

## Advanced API Proxy

The [proxy examples](/examples) show the optional proxy workflow: a credential
stays in the OS credential store while the app receives only a localhost proxy
URL and local token.
