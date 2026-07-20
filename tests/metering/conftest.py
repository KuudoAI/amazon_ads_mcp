"""Fixtures for tests/metering/.

Only `test_conformance.py` (via `amazon_ads_mcp.metering.conformance`)
reads `os.environ` directly for its policy -- every other test module
under `tests/metering/` builds its own explicit env dict (see
`_support.base_env`) and never depends on this fixture. Mirrors the
integration guide's §4 "CI environment" block (conformance-only fakes,
never a real credential/endpoint) so `uv run pytest tests/metering -q`
is self-sufficient locally, the same values the CI `metering` job (Task
22 ruling #9) exports before running the identical command.

Deliberately excludes `METERING_OUTBOX_PATH` (the guide's own CI block
doesn't set it either) -- `metering.conformance._env`'s `setdefault` then
keeps each test's own `tmp_path`-scoped outbox path, preserving isolation
between tests.
"""

from __future__ import annotations

import asyncio

import pytest

from amazon_ads_mcp.metering.adapter import get_metering_runtime, set_metering_runtime

_CI_ENV_BLOCK = {
    "METERING_ENABLED": "true",
    "METERING_UPSTREAM_HOSTS": "advertising-api.amazon.com",
    "METERING_UPSTREAM_SERVICE": "amazon_ads",
    "METERING_ENDPOINT": "https://ingest.example-metering.test/v1/usage/batches",
    "METERING_DEPLOYMENT_ID": "ci",
    "METERING_INSTANCE_ID": "ci-1",
    "METERING_KEY_ID": "ci-key-placeholder",
    "METERING_HMAC_SECRET": "ci-secret-placeholder",
    "METERING_OUTBOX_MAX_BYTES": "10000000",
}


@pytest.fixture(autouse=True)
def _conformance_ci_env(monkeypatch):
    for key, value in _CI_ENV_BLOCK.items():
        monkeypatch.setenv(key, value)
    yield


@pytest.fixture(autouse=True)
def _reset_metering_runtime_after_test():
    """Safety net (found the hard way: an earlier test in this file that
    asserted-and-failed left `set_metering_runtime()`'s module-level
    global still pointing at a real, started `MeteringRuntime` -- which
    then silently wrapped `AuthenticatedClient` construction in
    UNRELATED test files later in the same pytest session, e.g.
    `tests/unit/test_authenticated_client.py`). Every `tests/metering/`
    test that sets an active runtime already cleans up in its own
    `finally` block on the happy path; this fixture guarantees the
    module-level global is back to `None` (and the runtime closed) even
    when a test fails before reaching its own cleanup, so a bug or
    assertion failure in ONE test can never leak metering state into
    another test file.
    """
    yield
    runtime = get_metering_runtime()
    if runtime is None:
        return
    set_metering_runtime(None)
    try:
        asyncio.run(runtime.aclose())
    except Exception:
        pass
