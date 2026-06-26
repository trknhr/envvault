# Codex Example

This example shows the repository-safe shape for running Codex with EnvVault-managed credentials.

`.env.example` contains only a EnvVault reference:

```dotenv
BACKEND_A_TOKEN=envvault://backend-a/dev
```

After initializing EnvVault and creating the `backend-a/dev` process profile, run:

```bash
envvault exec --env-file examples/codex/.env.example -- codex
```

The child process receives a short-lived JWT in `BACKEND_A_TOKEN`. The repository still contains only the profile reference.
