# syntax=docker/dockerfile:1.6

FROM python:3.14-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH="/app/src" \
    PATH="/opt/venv/bin:/root/.local/bin:$PATH"

WORKDIR /app

# Install system dependencies and uv (kept minimal)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl \
  && rm -rf /var/lib/apt/lists/* \
  && curl -LsSf https://astral.sh/uv/install.sh | sh

# Copy dependency metadata, source, and README (required by poetry-core build)
COPY pyproject.toml uv.lock README.md ./
COPY src/ src/
ENV UV_PROJECT_ENVIRONMENT=/opt/venv
RUN uv venv /opt/venv && \
    uv sync --no-dev --frozen

# Copy remaining application files (configs, openapi specs, etc.)
COPY . .

# Create cache and data directories for persistent storage
RUN mkdir -p /app/.cache/amazon-ads-mcp /app/data && \
    chmod 755 /app/.cache /app/.cache/amazon-ads-mcp /app/data

# Build provenance: embed the commit SHA and build timestamp so the
# running container can self-report which source it was built from.
# Populate via `docker build --build-arg GIT_SHA=$(git rev-parse --short HEAD)`
# or via docker-compose `build.args`. Defaults keep images reproducible
# when args are omitted.
ARG GIT_SHA=unknown
ARG BUILD_TIME=unknown
ENV AMAZON_ADS_MCP_GIT_SHA=$GIT_SHA \
    AMAZON_ADS_MCP_BUILD_TIME=$BUILD_TIME

# Runtime configuration
ENV TRANSPORT=streamable-http \
    HOST=0.0.0.0 \
    PORT=8000

EXPOSE 8000

CMD ["python", "-m", "amazon_ads_mcp.server", "--transport", "streamable-http", "--host", "0.0.0.0", "--port", "9080"]
