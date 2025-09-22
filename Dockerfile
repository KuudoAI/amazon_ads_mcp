# syntax=docker/dockerfile:1.6

FROM python:3.13-slim AS base

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

# Prepare virtual environment and install Python dependencies with uv
COPY requirements.txt ./
# Create venv at /opt/venv and install deps using uv (resolver) to include transitive deps
RUN uv venv /opt/venv && \
    uv pip install -r requirements.txt

# Copy application source
COPY . .

# Create cache and data directories for persistent storage
RUN mkdir -p /app/.cache/amazon-ads-mcp /app/data && \
    chmod 755 /app/.cache /app/.cache/amazon-ads-mcp /app/data

# Runtime configuration
ENV TRANSPORT=streamable-http \
    HOST=0.0.0.0 \
    PORT=9080

EXPOSE 9080

CMD ["python", "-m", "amazon_ads_mcp.server", "--transport", "streamable-http", "--host", "0.0.0.0", "--port", "9080"]
