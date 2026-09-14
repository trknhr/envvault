ARG GO_VERSION=1.25.0
ARG NODE_VERSION=22.22.2

FROM golang:${GO_VERSION}-bookworm AS go-toolchain

FROM node:${NODE_VERSION}-bookworm-slim

ARG CODEX_VERSION=0.147.0

COPY --from=go-toolchain /usr/local/go /usr/local/go

ENV GOCACHE=/workspace/.envvault-cache/go-build \
    GOMODCACHE=/workspace/.envvault-cache/go/pkg/mod \
    GOPATH=/workspace/.envvault-cache/go \
    GOTOOLCHAIN=local \
    NPM_CONFIG_CACHE=/workspace/.envvault-cache/npm \
    PATH="/usr/local/go/bin:/workspace/.envvault-cache/go/bin:${PATH}"

RUN printf '%s\n' \
    'export PATH="/usr/local/go/bin:/workspace/.envvault-cache/go/bin:$PATH"' \
    > /etc/profile.d/envvault-go.sh

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
        build-essential \
        ca-certificates \
        git \
        openssh-client \
        ripgrep \
    && rm -rf /var/lib/apt/lists/*

RUN npm install --global "@openai/codex@${CODEX_VERSION}" \
    && npm cache clean --force

WORKDIR /workspace

USER node

CMD ["codex"]
