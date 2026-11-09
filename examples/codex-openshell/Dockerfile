ARG GO_VERSION=1.27.3
ARG NODE_VERSION=24.22.1

FROM golang:${GO_VERSION}-bookworm AS go-toolchain
FROM node:${NODE_VERSION}-bookworm-slim

ARG CODEX_VERSION=0.166.0

COPY --from=go-toolchain /usr/local/go /usr/local/go

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        git \
        openssh-client \
        ripgrep \
    && rm -rf /var/lib/apt/lists/*

# Give OpenShell one stable native executable path to match in network policy.
# The npm launcher normally selects a platform binary from its vendor directory.
RUN npm install --global "@openai/codex@${CODEX_VERSION}" \
    && native_codex="$(find /usr/local/lib/node_modules/@openai -type f -path '*/vendor/*/bin/codex')" \
    && test -n "$native_codex" \
    && test -x "$native_codex" \
    && cp -a "${native_codex%/bin/codex}" /opt/codex \
    && rm /usr/local/bin/codex \
    && ln -s /opt/codex/bin/codex /usr/local/bin/codex \
    && npm cache clean --force

RUN ln -s /usr/local/go/bin/go /usr/local/bin/go \
    && ln -s /usr/local/go/bin/gofmt /usr/local/bin/gofmt \
    && mkdir -p /workspace /home/node/.codex \
    && chown node:node /workspace /home/node/.codex

ENV GOTOOLCHAIN=local

WORKDIR /workspace
USER node
CMD ["/bin/bash", "-l"]
