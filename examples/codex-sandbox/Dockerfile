FROM node:22.22.2-bookworm-slim

ARG CODEX_VERSION=0.147.0

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends ca-certificates git openssh-client ripgrep \
    && rm -rf /var/lib/apt/lists/*

RUN npm install --global "@openai/codex@${CODEX_VERSION}" \
    && npm cache clean --force

WORKDIR /workspace

USER node

CMD ["codex"]
