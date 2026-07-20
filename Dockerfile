# syntax=docker/dockerfile:1.6
#
# Two-stage build for amazon-ads-mcp.
#
# Stage 1 (builder)  — install Python deps + project source into /opt/venv
#                      via uv, with cache mounts and bytecode pre-compilation.
# Stage 2 (runtime)  — copy /opt/venv into a fresh slim-bookworm, add a
#                      non-root user, embed build provenance, expose 8000,
#                      and run the MCP server.
#
# Build with provenance baked in:
#   docker build \
#     --build-arg GIT_SHA=$(git rev-parse --short HEAD) \
#     --build-arg BUILD_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
#     -t amazon-ads-mcp:latest .
#
# (docker-compose.yaml sets these args automatically when called with the
# matching env vars.)

# Pinned base versions. Bump together when upgrading toolchain.
ARG PYTHON_VERSION=3.14
ARG APP_UID=10001
ARG APP_GID=10001

# Metering (Task 22) is gated behind a build ARG, default OFF:
#
#   INCLUDE_METERING=false (default) -- `docker build .` with no
#     --build-arg needed. mcp-outbound-metering (a PRIVATE git
#     dependency, pyproject.toml [tool.uv.sources]) lives behind the
#     optional "metering" extra (pyproject.toml
#     [project.optional-dependencies]), never [project.dependencies], so
#     a default build never touches the private repo and needs no
#     credential at all.
#   INCLUDE_METERING=true -- installs the "metering" extra. Requires a
#     `billing_repo_token` BuildKit secret (a GitHub token with read
#     access to KuudoAI/billing) for `uv sync` to fetch the private
#     dependency, e.g.:
#       docker build --build-arg INCLUDE_METERING=true \
#         --secret id=billing_repo_token,env=BILLING_REPO_TOKEN .
#     The token is consumed via ephemeral GIT_CONFIG_* env vars scoped to
#     the single RUN step that needs it (see below) -- never written to
#     ~/.gitconfig or any other file, so it can never leak into an image
#     layer. At runtime, METERING_ENABLED=true resolves metering.yaml
#     from the packaged copy (amazon_ads_mcp/metering/metering.yaml,
#     fix round 2 deployment gap #1) with zero extra COPY needed here --
#     it ships inside the wheel/venv installed below.
#
# See docs/metering.md for both modes end to end, including the runtime
# env vars (METERING_ENABLED, METERING_UPSTREAM_HOSTS, etc.) neither mode
# sets here -- those are always supplied at `docker run`/compose time via
# a secrets manager, never baked into the image.
ARG INCLUDE_METERING=false

# Pull the uv standalone binary as a build-stage helper image. Pinning
# the uv tag (not :latest) keeps `uv sync` reproducible across builds.
FROM ghcr.io/astral-sh/uv:0.9.5 AS uv-bin

# ---------------------------------------------------------------------------
# Stage 1: builder
# ---------------------------------------------------------------------------
FROM python:${PYTHON_VERSION}-slim-bookworm AS builder

# Re-declare to bring the global ARG into this stage's scope.
ARG INCLUDE_METERING

# UV_LINK_MODE=copy is required when using the cache mount below — uv's
# default 'hardlink' mode breaks across the mount boundary.
# UV_COMPILE_BYTECODE=1 pre-compiles .pyc files at install time so the
# runtime image (which sets PYTHONDONTWRITEBYTECODE=1) can avoid the
# first-import compile cost.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1

WORKDIR /app

COPY --from=uv-bin /uv /uvx /bin/

# git is required to resolve mcp-outbound-metering (a git dependency,
# pyproject.toml [tool.uv.sources]) whenever INCLUDE_METERING=true --
# python:*-slim-bookworm does not ship it. Installed unconditionally
# (cheap, cached, and this builder stage is discarded -- only /opt/venv
# is copied into the runtime image below, so this never affects final
# image size or the default INCLUDE_METERING=false build's footprint).
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends git

# Layer-cache friendly: install the dep graph before copying source.
# `--no-install-project --no-editable` resolves and installs only deps so
# this layer survives source-only changes.
#
# The `billing_repo_token` secret is only ever READ inside this one RUN
# step, and only when INCLUDE_METERING=true -- via GIT_CONFIG_COUNT/
# GIT_CONFIG_KEY_0/GIT_CONFIG_VALUE_0 env vars scoped to this shell
# process only. Nothing writes it to ~/.gitconfig or any other file, so
# it never persists into this (or any) image layer. `required=false`
# keeps the default INCLUDE_METERING=false build working with no secret
# provided at all.
COPY pyproject.toml uv.lock README.md ./
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=secret,id=billing_repo_token,required=false \
    uv venv /opt/venv && \
    EXTRAS="--extra code-mode" && \
    if [ "$INCLUDE_METERING" = "true" ]; then \
        EXTRAS="$EXTRAS --extra metering"; \
        if [ -s /run/secrets/billing_repo_token ]; then \
            export GIT_CONFIG_COUNT=1; \
            export GIT_CONFIG_KEY_0="url.https://x-access-token:$(cat /run/secrets/billing_repo_token)@github.com/KuudoAI/billing.insteadOf"; \
            export GIT_CONFIG_VALUE_0="https://github.com/KuudoAI/billing"; \
        fi; \
    fi && \
    uv sync --no-dev --frozen $EXTRAS --no-install-project --no-editable

# Now bring in the project itself and install it on top of the cached deps.
# pyproject.toml uses build_package.py as an in-tree PEP 517 backend.
# Same EXTRAS/secret handling as above -- uv's extras set must stay
# consistent across both syncs, or this second (no-extras) sync would
# uninstall mcp-outbound-metering that the first sync just installed.
COPY build_package.py ./
COPY src/ src/
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=secret,id=billing_repo_token,required=false \
    EXTRAS="--extra code-mode" && \
    if [ "$INCLUDE_METERING" = "true" ]; then \
        EXTRAS="$EXTRAS --extra metering"; \
        if [ -s /run/secrets/billing_repo_token ]; then \
            export GIT_CONFIG_COUNT=1; \
            export GIT_CONFIG_KEY_0="url.https://x-access-token:$(cat /run/secrets/billing_repo_token)@github.com/KuudoAI/billing.insteadOf"; \
            export GIT_CONFIG_VALUE_0="https://github.com/KuudoAI/billing"; \
        fi; \
    fi && \
    uv sync --no-dev --frozen $EXTRAS --no-editable

# ---------------------------------------------------------------------------
# Stage 2: runtime
# ---------------------------------------------------------------------------
FROM python:${PYTHON_VERSION}-slim-bookworm AS runtime

ARG APP_UID=10001
ARG APP_GID=10001

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

WORKDIR /app

# Copy the prepared virtualenv, plus the runtime-required OpenAPI artifacts
# (slim specs and overlays). The full `openapi/resources/` tree is dev-only
# and stays out of the runtime image.
COPY --from=builder /opt/venv /opt/venv
COPY dist/openapi/resources/ dist/openapi/resources/
COPY dist/openapi/overlays/ dist/openapi/overlays/
COPY scripts/docker-entrypoint.py /usr/local/bin/amazon-ads-mcp-entrypoint

# Create the unprivileged 'app' user, the writable runtime directories, and
# leave startup as root long enough for the entrypoint to repair mounted
# volume ownership before dropping privileges to `app`.
# 750 (rwx for owner, r-x for group) is tighter than 755 and matches the
# single-user model — no other accounts in this image need read access.
RUN groupadd --system --gid "${APP_GID}" app && \
    useradd --system --uid "${APP_UID}" --gid app --home-dir /app \
        --shell /usr/sbin/nologin app && \
    mkdir -p /app/.cache/amazon-ads-mcp /app/data && \
    chown -R app:app /app && \
    chmod 750 /app/.cache /app/.cache/amazon-ads-mcp /app/data && \
    chmod 755 /usr/local/bin/amazon-ads-mcp-entrypoint

# Build provenance: embed the commit SHA and build timestamp so the
# running container can self-report which source it was built from.
# Populate via `docker build --build-arg GIT_SHA=$(git rev-parse --short HEAD)`
# or via docker-compose `build.args`. Defaults keep images reproducible
# when args are omitted.
ARG GIT_SHA=unknown
ARG BUILD_TIME=unknown
ENV AMAZON_ADS_MCP_GIT_SHA=$GIT_SHA \
    AMAZON_ADS_MCP_BUILD_TIME=$BUILD_TIME

# OCI image labels — enable registry tooling, SBOM generators, and
# vulnerability scanners to identify and trace this image. Source/revision
# point at the canonical upstream; downstream forks should override
# `org.opencontainers.image.source` at build time.
LABEL org.opencontainers.image.title="amazon-ads-mcp" \
      org.opencontainers.image.description="Amazon Ads MCP server (FastMCP + Code Mode)" \
      org.opencontainers.image.source="https://github.com/KuudoAI/amazon_ads_mcp" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.revision="$GIT_SHA" \
      org.opencontainers.image.created="$BUILD_TIME"

# Runtime configuration. Keep parity with docker-compose.yaml's
# `environment:` block; if you change the default port here also update the
# EXPOSE line below. The healthcheck reads PORT at runtime.
ENV TRANSPORT=streamable-http \
    HOST=0.0.0.0 \
    PORT=8000

# The entrypoint starts as root, fixes named-volume ownership, then execs
# the command as the unprivileged app user.
USER root

EXPOSE 8000

# Container-level health probe — the server registers /health (and the
# k8s-conventional /healthz) at startup via
# `server_builder._setup_health_check`. Docker will mark the container
# `unhealthy` after `retries` consecutive failures so docker-compose
# `depends_on: condition: service_healthy` and orchestration restart
# policies behave correctly. `start-period` covers the initial OpenAPI
# spec load, which can take several seconds on first boot.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request,sys; \
port = __import__('os').environ.get('PORT', '8000'); \
sys.exit(0 if urllib.request.urlopen(f'http://127.0.0.1:{port}/health', timeout=4).status == 200 else 1)" \
    || exit 1

# Be explicit about the shutdown signal so `docker stop` / orchestrator
# rolling restarts deliver SIGTERM (Python's asyncio handles this cleanly
# via FastMCP's lifespan hooks).
STOPSIGNAL SIGTERM

ENTRYPOINT ["amazon-ads-mcp-entrypoint"]
CMD ["python", "-m", "amazon_ads_mcp.server", "--transport", "streamable-http", "--host", "0.0.0.0", "--port", "8000"]
