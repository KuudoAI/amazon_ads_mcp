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

Fix round 3, collection-safety gate
------------------------------------
`mcp-outbound-metering` now lives behind the optional `metering` extra
(fix round 2) -- it is ALSO absent on a 3.12 interpreter that never ran
`uv sync --extra metering`, exactly the `smoke` and `wheel-smoke` CI
jobs, which sync on Python 3.12 but never request the extra. Before this
gate, every `tests/metering/*.py` module's own `if sys.version_info >=
(3, 12): import mcp_outbound_metering...` guard evaluated the version
check as satisfied (3.12) and executed the import anyway, dying with a
collection-time `ModuleNotFoundError` -- CI logs showed exactly this:
"ImportError while importing test module .../test_attribution_event_flow.py
... ModuleNotFoundError: No module named 'mcp_outbound_metering'".

The fix below runs `pytest.importorskip("mcp_outbound_metering")` at
MODULE level, gated to `sys.version_info >= (3, 12)` ONLY -- this is the
critical detail. pytest always loads a directory's conftest.py before
collecting (importing) any test module inside it, so a module-level skip
here cleanly skips collection of the ENTIRE `tests/metering/` subtree as
one unit, before any test module's own top-level import ever runs.

The version guard on the `importorskip` itself matters because
`mcp_outbound_metering` is ALSO never installed on <3.12 (by design --
its own floor is 3.12) -- an unconditional `importorskip` here would
blanket-skip the whole directory on 3.10 too, silently swallowing the
~24 tests that are specifically written to run on EVERY Python version
(test_compat_guard.py, test_normalizer.py, test_attribution.py,
test_context.py, test_code_mode_attribution.py, test_lifespan_guard.py,
and several in test_packaged_config.py -- each documents in its own
module docstring why it deliberately isn't skipif-guarded). Gating this
check to 3.12+ leaves <3.12 collection completely untouched: those
version-independent tests keep running, and every version-gated test
module's own `pytestmark = pytest.mark.skipif(sys.version_info < (3,
12), ...)` keeps giving the clearer, more specific "why" for the 3.10
floor -- this conftest gate exists ONLY to catch "3.12+, but the package
genuinely isn't installed," the one case no existing guard covered.
"""

from __future__ import annotations

import asyncio
import sys

import pytest

if sys.version_info >= (3, 12):
    pytest.importorskip(
        "mcp_outbound_metering",
        reason="metering extra not installed (uv sync --extra metering)",
    )

from amazon_ads_mcp.metering.adapter import get_metering_runtime, set_metering_runtime  # noqa: E402

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
