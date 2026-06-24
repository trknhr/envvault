# Codex Example

This example shows the repository-safe shape for running Codex with Credlease-managed credentials.

`.env.example` contains only a Credlease reference:

```dotenv
BACKEND_A_TOKEN=credlease://backend-a/dev
```

After initializing Credlease and creating the `backend-a/dev` process profile, run:

```bash
credlease exec --env-file examples/codex/.env.example -- codex
```

The child process receives a short-lived JWT in `BACKEND_A_TOKEN`. The repository still contains only the profile reference.
