# The worker image for agent jobs on a member's own machine (docs/MACHINES.md §5c): Claude Code — and the Codex CLI and
# the Gemini CLI, for work on a member's own Codex or Gemini slot (docs/WORK-ROUTING.md §9) — in a Linux VM (Apple
# `container` on a Mac, Podman + krun/gVisor on Linux) that clones a repository over SSH through the job's broker, works
# on a task/* branch, and pushes it. Nothing here holds a secret: the model token is a placeholder the Gate replaces,
# and the deploy key stays in the Gate's SSH proxy.
#
# The VM has no general internet (only the broker's explicit secret form, SSH and the media doors), so a job can only
# use what this image already has. That is why the Gate's node_modules are baked in below.
#
# Build it with `node/images/dev/build.sh` (it checks disk first, and builds from a small context holding only this file
# and the Gate's package.json and pnpm-lock.yaml).
# The node looks for `pavilion-dev:2` (or `agent_image` in its config.json; an older `pavilion-dev:1` is used for Claude
# work only) and reports `agent-jobs` and `agent-jobs:<harness>` for each CLI below once it is there.
FROM docker.io/library/node:24-bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive
# git and ssh for the repository; nc for the ProxyCommand to the broker; coreutils' timeout; the small tools agents reach for.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git openssh-client ca-certificates netcat-openbsd coreutils procps \
      ripgrep jq less python3 \
 && rm -rf /var/lib/apt/lists/*

# Claude Code, the official package, unmodified. Its sign-in is never baked in.
ARG CLAUDE_CODE_VERSION=latest
RUN npm install -g "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}" && npm cache clean --force

# The Codex CLI and the Gemini CLI, the official packages, unmodified. Neither sign-in is baked in: a Codex job gets a
# placeholder auth.json and a Gemini job a placeholder access token, and the node's broker adds the member's own
# credential on the way out (node/src/slot_auth.rs). 0.153.4 and 0.54.4 are the versions whose endpoints were checked.
ARG CODEX_VERSION=0.153.4
ARG GEMINI_CLI_VERSION=0.54.4
RUN npm install -g "@openai/codex@${CODEX_VERSION}" "@google/gemini-cli@${GEMINI_CLI_VERSION}" && npm cache clean --force

# The Gate's dependencies, installed from its lock file, so `npx vitest run` and `npx tsc` work with no registry. The
# job script links gate/node_modules here when the repository's lock file matches this one (lock.sha256).
# The Gate is a pnpm project (gate/pnpm-lock.yaml, lockfile v9), so its dependencies are installed with pnpm, pinned.
ARG PNPM_VERSION=11.9.0
# pnpm-workspace.yaml says which dependencies may run install scripts (esbuild, workerd); pnpm 11 refuses without it.
# Built outside Cloud Pavilion's repository, the three files are empty and this step installs nothing.
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml /opt/pavilion/gate-deps/
RUN if [ -s /opt/pavilion/gate-deps/pnpm-lock.yaml ]; then \
      npm install -g "pnpm@${PNPM_VERSION}" \
      && cd /opt/pavilion/gate-deps \
      && pnpm install --frozen-lockfile \
      && pnpm store prune \
      && npm cache clean --force \
      && sha256sum pnpm-lock.yaml | cut -d' ' -f1 > lock.sha256; \
    fi

# A non-root user does the work. (The base image's `node` user is uid 1000; this one is separate.)
RUN useradd --create-home --uid 1001 --shell /bin/bash agent \
 && mkdir -p /work \
 && chown agent:agent /work \
 && chown -R agent:agent /opt/pavilion/gate-deps
USER agent
ENV HOME=/home/agent \
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 \
    DISABLE_AUTOUPDATER=1 \
    IS_SANDBOX=1
WORKDIR /work
LABEL pavilion.image="agent-dev" pavilion.image.version="2" pavilion.image.harnesses="claude-code,codex,gemini-cli"
CMD ["sleep", "infinity"]
