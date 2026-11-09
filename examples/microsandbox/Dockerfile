ARG GO_VERSION=1.27.3
ARG NODE_VERSION=24.22.1
FROM golang:${GO_VERSION}-bookworm AS go-toolchain
FROM node:${NODE_VERSION}-bookworm-slim
ARG CODEX_VERSION=0.166.0
COPY --from=go-toolchain /usr/local/go /usr/local/go
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
        build-essential ca-certificates curl git openssh-client ripgrep util-linux \
    && rm -rf /var/lib/apt/lists/*
RUN npm install --global "@openai/codex@${CODEX_VERSION}" \
    && native_codex="$(find /usr/local/lib/node_modules/@openai -type f -path '*/vendor/*/bin/codex')" \
    && test -n "$native_codex" && test -x "$native_codex" \
    && cp -a "${native_codex%/bin/codex}" /opt/codex \
    && rm /usr/local/bin/codex \
    && ln -s /opt/codex/bin/codex /usr/local/bin/codex \
    && npm cache clean --force
RUN ln -s /usr/local/go/bin/go /usr/local/bin/go \
    && ln -s /usr/local/go/bin/gofmt /usr/local/bin/gofmt \
    && mkdir -p /workspace /home/agent
COPY agent-entrypoint /usr/local/bin/envvault-agent-exec
COPY git-credential-envvault /usr/local/bin/git-credential-envvault
RUN chmod 0755 /usr/local/bin/envvault-agent-exec \
    && chmod 0755 /usr/local/bin/git-credential-envvault \
    && groupmod --new-name agent node \
    && usermod --login agent --home /home/agent --shell /bin/bash node
ARG GH_VERSION=2.102.0
ARG TARGETARCH
RUN set -eu; \
    case "$TARGETARCH" in \
      arm64) gh_checksum=7862c86c72f43df3a2d93ddde6f473285b4e2af61b494849846827e513ef6484 ;; \
      amd64) gh_checksum=bb766f710eef8ede859c18578c72c327597cd4c8a85b06001b1f3843c6019386 ;; \
      *) exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/gh.tar.gz "https://github.com/cli/cli/releases/download/v${GH_VERSION}/gh_${GH_VERSION}_linux_${TARGETARCH}.tar.gz"; \
    printf '%s  /tmp/gh.tar.gz\n' "$gh_checksum" | sha256sum --check -; \
    tar -xzf /tmp/gh.tar.gz --strip-components=2 -C /usr/local/bin "gh_${GH_VERSION}_linux_${TARGETARCH}/bin/gh"; \
    rm /tmp/gh.tar.gz
ENV GOTOOLCHAIN=local
WORKDIR /workspace
CMD ["/bin/bash", "-l"]
