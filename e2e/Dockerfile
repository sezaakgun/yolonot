# Multi-harness E2E test environment for yolonot (linux/arm64 & linux/amd64).
# Build & run via: ./scripts/e2e-docker
FROM golang:1.26-bookworm

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    bubblewrap \
    bzip2 \
    ca-certificates \
    curl \
    git \
    jq \
    libgomp1 \
    libsecret-1-0 \
    locales \
    procps \
    python3 \
    python3-venv \
    ripgrep \
    sqlite3 \
    tmux \
    unzip \
    xz-utils \
    && sed -i '/en_US.UTF-8/s/^# //g' /etc/locale.gen && locale-gen \
    && rm -rf /var/lib/apt/lists/*

ENV LANG=en_US.UTF-8 \
    LC_ALL=en_US.UTF-8

# Node.js 22 LTS (supports native TypeScript execution for plugin shim tests)
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

# uv / uvx (for Python-based agent CLIs)
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/

# Create unprivileged test user (required by Claude Code & realistic HOME layout)
RUN useradd -m -s /bin/bash e2e \
    && mkdir -p /go/pkg/mod /home/e2e/.cache/go-build \
    && chown -R e2e:e2e /go /home/e2e

USER e2e
WORKDIR /home/e2e

ENV HOME=/home/e2e \
    NPM_CONFIG_PREFIX=/home/e2e/.npm-global \
    BUN_INSTALL=/home/e2e/.bun \
    PATH="/home/e2e/.local/bin:/home/e2e/.npm-global/bin:/home/e2e/.bun/bin:/usr/local/go/bin:/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

RUN mkdir -p /home/e2e/.local/bin /home/e2e/.npm-global

# Bun runtime (used by OpenCode plugins)
RUN curl -fsSL https://bun.sh/install | bash

# 1. Node/npm-distributed agent CLIs (installed individually so versions/errors are clear)
RUN for pkg in \
      "@openai/codex" \
      "@earendil-works/pi-coding-agent" \
      "@qwen-code/qwen-code" \
      "@kilocode/cli" \
      "cline" \
      "@github/copilot" \
      "openclaw" \
      "@sourcegraph/amp" \
      "@xai-official/grok" \
      "zcode-app-cli"; \
    do \
      echo "=== Installing npm package: $pkg ===" && \
      npm install -g --no-fund --no-audit "$pkg" || echo "WARN: failed to install $pkg"; \
    done && npm cache clean --force

# 2. Standalone native Linux agent CLIs (Claude, Antigravity, Cursor, Crush, Goose, Kiro)
RUN set -eux; \
    ARCH="$(uname -m)"; \
    echo "=== Installing Claude Code ==="; \
    (curl -fsSL https://claude.ai/install.sh | bash) || echo "WARN: claude install failed"; \
    echo "=== Installing Antigravity CLI (agy) ==="; \
    (curl -fsSL https://antigravity.google/cli/install.sh | bash -s -- -d /home/e2e/.local/bin) || echo "WARN: agy install failed"; \
    echo "=== Installing Cursor CLI (cursor-agent) ==="; \
    (curl -fsSL https://cursor.com/install | bash) || echo "WARN: cursor-agent install failed"; \
    echo "=== Installing Charmbracelet Crush ==="; \
    CRUSH_ARCH="x86_64"; \
    if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then CRUSH_ARCH="arm64"; fi; \
    CRUSH_URL="$(curl -fsSL https://api.github.com/repos/charmbracelet/crush/releases/latest | jq -r ".assets[] | select(.name | test(\"Linux_${CRUSH_ARCH}\\\\.tar\\\\.gz$\")) | .browser_download_url" | head -n1)"; \
    if [ -n "$CRUSH_URL" ] && [ "$CRUSH_URL" != "null" ]; then \
      mkdir -p /tmp/crush && curl -fsSL "$CRUSH_URL" | tar -xz -C /tmp/crush && \
      find /tmp/crush -type f -name crush -exec mv {} /home/e2e/.local/bin/crush \; && \
      chmod +x /home/e2e/.local/bin/crush && rm -rf /tmp/crush; \
    fi; \
    echo "=== Installing Goose CLI ==="; \
    (curl -fsSL https://github.com/aaif-goose/goose/releases/download/stable/download_cli.sh | CONFIGURE=false bash) || echo "WARN: goose install failed"; \
    echo "=== Installing Kiro CLI ==="; \
    KIRO_ARCH="x86_64"; \
    if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then KIRO_ARCH="aarch64"; fi; \
    (mkdir -p /tmp/kiro && \
      curl --proto '=https' --tlsv1.2 -fsSL "https://desktop-release.q.us-east-1.amazonaws.com/latest/kirocli-${KIRO_ARCH}-linux.zip" -o /tmp/kiro/kirocli.zip && \
      unzip -q /tmp/kiro/kirocli.zip -d /tmp/kiro && \
      find /tmp/kiro -type f \( -name "kiro-cli" -o -name "kiro-cli-chat" \) -exec cp {} /home/e2e/.local/bin/ \; && \
      chmod +x /home/e2e/.local/bin/kiro-cli*) || echo "WARN: kiro-cli install failed"; \
    rm -rf /tmp/kiro

# 3. Python uv-distributed agent CLIs (Reflection Mirror, OpenHands)
RUN for tool in "reflection-mirror" "openhands"; do \
      echo "=== Installing uv tool: $tool ===" && \
      uv tool install "$tool" || echo "WARN: uv tool install $tool failed"; \
    done && uv cache clean

# Pre-warm Go module cache, install OpenCode v2 & Kimi Code CLI, and wire Linux helper symlinks
COPY --chown=e2e:e2e go.mod go.sum /tmp/gomod/
RUN set -eux; \
    cd /tmp/gomod && go mod download && rm -rf /tmp/gomod; \
    ARCH="$(uname -m)"; \
    OC_ARCH="x64"; \
    if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then OC_ARCH="arm64"; fi; \
    OC_URL="$(curl -fsSL "https://api.github.com/repos/anomalyco/opencode/releases?per_page=15" | jq -r "[.[] | select(.tag_name | test(\"^v[0-9]+\\\\.\"))][0].assets[] | select(.name == \"opencode-linux-${OC_ARCH}.tar.gz\") | .browser_download_url" | head -n1)"; \
    if [ -n "$OC_URL" ] && [ "$OC_URL" != "null" ]; then \
      mkdir -p /tmp/oc2 && curl -fsSL "$OC_URL" | tar -xz -C /tmp/oc2 && \
      find /tmp/oc2 -type f -name opencode -exec mv {} /home/e2e/.local/bin/opencode \; && \
      chmod +x /home/e2e/.local/bin/opencode && rm -rf /tmp/oc2; \
    else \
      echo "WARN: opencode v2 download URL not found"; \
    fi; \
    (curl -fsSL https://code.kimi.com/kimi-code/install.sh | bash && ln -sf /home/e2e/.kimi-code/bin/kimi /home/e2e/.local/bin/kimi || echo "WARN: kimi-code install failed"); \
    CODEX_NATIVE="$(find /home/e2e/.npm-global/lib/node_modules/@openai/codex -type f -path '*/bin/codex' 2>/dev/null | head -n1)"; \
    if [ -n "$CODEX_NATIVE" ]; then ln -sf "$CODEX_NATIVE" /home/e2e/.local/bin/codex-linux-sandbox; fi; \
    if [ -x /home/e2e/.local/bin/kiro-cli ] && [ ! -e /home/e2e/.local/bin/kiro-cli-chat ]; then \
      ln -s /home/e2e/.local/bin/kiro-cli /home/e2e/.local/bin/kiro-cli-chat; \
    fi; \
    printf '\nexport PATH="/home/e2e/.local/bin:/home/e2e/.kimi-code/bin:/home/e2e/.npm-global/bin:/home/e2e/.bun/bin:/usr/local/go/bin:/go/bin:$PATH"\n' >> /home/e2e/.profile; \
    printf '\nexport PATH="/home/e2e/.local/bin:/home/e2e/.kimi-code/bin:/home/e2e/.npm-global/bin:/home/e2e/.bun/bin:/usr/local/go/bin:/go/bin:$PATH"\n' >> /home/e2e/.bashrc

WORKDIR /workspace
