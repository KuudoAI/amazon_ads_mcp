# Usage metering (Task 22)

Meters every real Amazon Ads API call through `AuthenticatedClient` (both
construction paths, plus `ResilientAuthenticatedClient`) via the
`mcp-outbound-metering` producer runtime (billing repo,
`packages/python/mcp_outbound_metering`). OAuth/OpenBridge/Kuudo provider
clients are structurally unmetered -- they never construct
`AuthenticatedClient`. Off by default everywhere; enabling it is an
explicit, opt-in operator decision, described below.

## Two install modes

`mcp-outbound-metering` is a **private** git dependency (`pyproject.toml`
`[tool.uv.sources]`, `KuudoAI/billing`), Python>=3.12 only, and lives
behind the optional `metering` extra -- **never** a base dependency. A
plain install/sync (`uv sync`, `pip install .`, the default Docker build)
never touches the private repo and needs no credential, on any Python
version.

### 1. Local / non-Docker install

```bash
# Default -- no metering support, no private-repo access:
uv sync
pip install .

# With metering support (Python>=3.12 required):
uv sync --extra metering
pip install '.[metering]'
```

### 2. Docker

The `Dockerfile` gates the extra behind a build ARG, default OFF:

```bash
# Default -- token-free, exactly like every other default build:
docker build -t amazon-ads-mcp .

# With metering support -- requires a `billing_repo_token` BuildKit
# secret (a GitHub token with read access to KuudoAI/billing):
docker build --build-arg INCLUDE_METERING=true \
  --secret id=billing_repo_token,env=BILLING_REPO_TOKEN \
  -t amazon-ads-mcp .
```

`docker-compose.yaml` reads the same toggle from an `INCLUDE_METERING`
shell/`.env` variable (default `false`) for `docker compose build`.

The token is consumed entirely through ephemeral
`GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_0`/`GIT_CONFIG_VALUE_0` environment
variables scoped to the single `RUN` step that needs them -- it is never
written to `~/.gitconfig` or any other file, so it cannot leak into an
image layer even if that layer is cached/pushed. See the `Dockerfile`'s
own comments for the exact mechanism.

## Config resolution (works in every deployment shape)

`metering.yaml` is tracked at the repo root **and** packaged as
`amazon_ads_mcp/metering/metering.yaml` (byte-identical -- a drift-guard
test fails loudly if they ever diverge). A Docker runtime image copies
the venv + `dist/openapi/` + the entrypoint into `/app`, never a repo
checkout, and a wheel install only ships packaged resources -- so
`amazon_ads_mcp.metering.config.resolve_config_path()` resolves in this
order:

1. `METERING_CONFIG` env var, if set -- explicit operator override.
2. `./metering.yaml` relative to CWD, if present -- dev convenience
   (running from a repo checkout finds the tracked file with zero
   configuration).
3. The packaged copy, via `importlib.resources` -- works from a wheel
   install and a Docker image's site-packages, independent of CWD. This
   is what a packaged/Docker deployment actually uses.

## Enabling at runtime

None of the `METERING_*` values are ever baked into the image or the
repo -- they are always supplied at `docker run`/compose time via a
secrets manager, exactly like every other credential this project uses.
Minimum set to enable:

```bash
METERING_ENABLED=true
METERING_UPSTREAM_HOSTS=advertising-api.amazon.com,advertising-api-eu.amazon.com,advertising-api-fe.amazon.com
METERING_UPSTREAM_SERVICE=amazon_ads
METERING_ENDPOINT=<your ingest endpoint>
METERING_DEPLOYMENT_ID=<per-deployment id>
METERING_INSTANCE_ID=<per-replica id>
METERING_KEY_ID=<signing key id>
METERING_HMAC_SECRET=<signing secret>
METERING_OUTBOX_MAX_BYTES=10000000
```

**Regional hosts, production**: `METERING_UPSTREAM_HOSTS` must list all
three Amazon Ads regional hosts before enabling in production --
`advertising-api.amazon.com`, `advertising-api-eu.amazon.com`,
`advertising-api-fe.amazon.com` -- plus the `-test` sandbox variants if
`AMAZON_ADS_SANDBOX_MODE` is used. The host match is exact, never a
suffix/wildcard (`RegionConfig.API_HOSTS`, `utils/region_config.py`), and
`metering.yaml`'s `disallowed_host_action` is `reject`: listing only the
NA host rejects every EU/FE request outright the moment an
identity/marketplace routes to a regional endpoint that isn't
allowlisted.

**Billing-critical startup rule**: `METERING_ENABLED=true` (exactly,
case-insensitive) that fails to start (Python<3.12, the `metering` extra
not installed, a bad config, etc.) **fails server startup** -- the server
refuses to accept traffic without metering rather than silently running
unmetered (design §7.3). Any other truthy-but-not-exactly-`"true"` value
attempts startup (so a genuine misconfiguration is logged, not silently
ignored) but degrades non-fatally on failure. Unset/`false`/empty is a
silent no-op, the default.

If `METERING_ENABLED=true` (strict) and the `metering` extra isn't
installed, startup fails with a message naming the exact fix:

```
METERING_ENABLED=true but metering is unavailable (requires Python>=3.12
and the optional 'metering' extra installed -- run pip/uv install
'amazon-ads-mcp[metering]'); refusing to start without metering
```

## CI

`.github/workflows/ci.yml`'s `metering` job (Python 3.12 only) syncs with
`--extra metering` (needs `BILLING_REPO_TOKEN`), runs
`uv run pytest tests/metering -q`, then `uv run mcp-metering verify
--config metering.yaml --harness
amazon_ads_mcp.metering.conformance:create_conformance_harness
--skip-ingest`. Every other job (`smoke`, `tests`, `catalog-negative`,
`wheel-smoke`) runs a plain `uv sync --frozen` with no extra and never
touches the private repo, on any Python version in their matrices.

## Source layout

- `metering.yaml` (repo root, tracked) / `src/amazon_ads_mcp/metering/metering.yaml`
  (packaged, byte-identical) -- the adapter config.
- `src/amazon_ads_mcp/metering/` -- `compat.py` (the <3.12 + missing-extra
  guard), `adapter.py` (`LazyMeteredTransport`, the transport-install
  seam), `attribution.py` (`tool_name` ContextVar + middleware),
  `context.py`/`normalizer.py` (dimension + path-normalizer providers),
  `config.py` (config path resolution), `lifespan.py` (start/stop +
  health payload), `conformance.py` (the `mcp-metering verify` /
  `ProducerConformanceSuite` harness factory).
- `tests/metering/` -- the full test suite (skipif-guarded to Python>=3.12
  wherever it needs the real `mcp_outbound_metering` package).
