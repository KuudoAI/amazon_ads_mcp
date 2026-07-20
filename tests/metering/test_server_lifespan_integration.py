"""Integration test for the REAL `server_lifespan()` wiring (Task 22
ruling #8) -- not just the isolated `metering.lifespan` helper module
(`test_lifespan.py`), but the actual async context manager
`server/mcp_server.py` passes to FastMCP.

Verified repo fact (found running the full suite, not just tests/metering
in isolation): `server/mcp_server.py` module docstring aside, its
`server_lifespan()` guards the ENTIRE shutdown block (including where
this task's `stop_metering()` call was added) behind a process-lifetime
module global, `_cleanup_done`, that is set `True` exactly once and never
reset -- correct for a real single-process server (shutdown happens once,
ever), but it means a SECOND `server_lifespan()` invocation in the same
test process (e.g. another test file's fixture, such as
`tests/integration/test_inmemory_mcp_client.py`'s `mcp_server` fixture,
which drives a real FastMCP `Client(...)` startup+shutdown cycle) leaves
the shutdown block a no-op for every later test that also invokes
`server_lifespan()` directly, this file included. This is pre-existing
behavior this task must not change (out of scope, and correct for real
process lifecycle) -- these tests instead reset `_cleanup_done` to
`False` via monkeypatch before each scenario, so each one genuinely
exercises the real shutdown path regardless of test execution order.
"""

from __future__ import annotations

import asyncio
import sys
from types import SimpleNamespace

import pytest

pytestmark = pytest.mark.skipif(
    sys.version_info < (3, 12), reason="metering requires Python>=3.12"
)

if sys.version_info >= (3, 12):
    from amazon_ads_mcp.metering.adapter import get_metering_runtime

    from ._support import CONFIG_PATH, base_env


def test_server_lifespan_starts_and_stops_metering(tmp_path, monkeypatch) -> None:
    from amazon_ads_mcp.server import mcp_server
    from amazon_ads_mcp.server.mcp_server import server_lifespan

    monkeypatch.setattr(mcp_server, "_cleanup_done", False)

    env = base_env(tmp_path)
    env["METERING_CONFIG"] = str(CONFIG_PATH)
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    async def scenario():
        assert get_metering_runtime() is None
        async with server_lifespan(SimpleNamespace()):
            assert get_metering_runtime() is not None
        assert get_metering_runtime() is None

    asyncio.run(scenario())


def test_server_lifespan_without_metering_enabled_is_unaffected(monkeypatch) -> None:
    """The overwhelmingly common case: METERING_ENABLED unset. Lifespan
    behaves exactly as it did before this integration existed."""
    from amazon_ads_mcp.server import mcp_server
    from amazon_ads_mcp.server.mcp_server import server_lifespan

    monkeypatch.setattr(mcp_server, "_cleanup_done", False)
    monkeypatch.delenv("METERING_ENABLED", raising=False)

    async def scenario():
        assert get_metering_runtime() is None
        async with server_lifespan(SimpleNamespace()):
            assert get_metering_runtime() is None
        assert get_metering_runtime() is None

    asyncio.run(scenario())
