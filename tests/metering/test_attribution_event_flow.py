"""§8.3 "Attribution", end-to-end through the real metering pipeline: the
tool_name dimension flows from `ToolAttributionMiddleware`/`code_mode.py`'s
bridge into the recorded usage event, missing attribution never suppresses
the event, and ordinary vs Code Mode dispatch produce identical event
counts (Task 22 ruling #5).

`test_attribution.py` and `test_code_mode_attribution.py` cover the
ContextVar/middleware/bridge primitives in isolation without a metering
package dependency; this module drives the SAME primitives through a real
`AuthenticatedClient` + `MeteringRuntime` to prove the dimension actually
lands on a recorded event.
"""

from __future__ import annotations

import asyncio
import sys
from types import SimpleNamespace
from unittest.mock import patch

import httpx
import pytest

pytestmark = pytest.mark.skipif(
    sys.version_info < (3, 12), reason="metering requires Python>=3.12"
)

if sys.version_info >= (3, 12):
    from amazon_ads_mcp.metering.adapter import set_metering_runtime
    from amazon_ads_mcp.metering.attribution import ToolAttributionMiddleware
    from amazon_ads_mcp.server.code_mode import create_auth_bridging_sandbox_provider
    from amazon_ads_mcp.utils.http_client import AuthenticatedClient

    from ._support import ALLOWED_HOST, FakeAuthManager, RecordingIngestTransport, build_runtime


def test_middleware_sets_tool_name_dimension_on_recorded_event(tmp_path) -> None:
    async def scenario():
        ingest = RecordingIngestTransport()
        runtime = await build_runtime(tmp_path, ingest=ingest)
        set_metering_runtime(runtime)
        try:
            middleware = ToolAttributionMiddleware()

            async def call_next(context):
                upstream = httpx.MockTransport(lambda request: httpx.Response(200))
                client = AuthenticatedClient(transport=upstream, auth_manager=FakeAuthManager())
                try:
                    return await client.get(f"https://{ALLOWED_HOST}/v2/profiles")
                finally:
                    await client.aclose()

            context = SimpleNamespace(message=SimpleNamespace(name="search_profiles"))
            response = await middleware.on_call_tool(context, call_next)
            assert response.status_code == 200

            events = await ingest.wait_for_event_count(1)
        finally:
            set_metering_runtime(None)
            await runtime.aclose()

        assert len(events) == 1
        assert events[0]["data"]["dimensions"]["tool_name"] == "search_profiles"

    asyncio.run(scenario())


def test_missing_attribution_never_suppresses_the_event(tmp_path) -> None:
    async def scenario():
        ingest = RecordingIngestTransport()
        runtime = await build_runtime(tmp_path, ingest=ingest)
        set_metering_runtime(runtime)
        try:
            # No tool_name_scope, no middleware -- an HTTP call made
            # entirely outside any attribution scope.
            upstream = httpx.MockTransport(lambda request: httpx.Response(200))
            client = AuthenticatedClient(transport=upstream, auth_manager=FakeAuthManager())
            try:
                response = await client.get(f"https://{ALLOWED_HOST}/v2/profiles")
                assert response.status_code == 200
            finally:
                await client.aclose()

            events = await ingest.wait_for_event_count(1)
        finally:
            set_metering_runtime(None)
            await runtime.aclose()

        # The event was still emitted -- dimension absent, not the event.
        assert len(events) == 1
        assert events[0]["data"]["dimensions"].get("tool_name") is None

    asyncio.run(scenario())


class _DummyContext:
    def __init__(self) -> None:
        self.request_context = object()
        self.state: dict = {}

    async def get_state(self, key):
        return self.state.get(key)

    async def set_state(self, key, value):
        self.state[key] = value


def test_ordinary_and_code_mode_dispatch_produce_identical_event_counts(tmp_path) -> None:
    """§8.3: "ordinary vs code-mode counts identical." Both paths make
    exactly one metered HTTP call per tool invocation; Code Mode's bridge
    must neither drop nor duplicate the resulting usage event relative to
    the ordinary middleware path."""

    async def make_one_metered_call() -> httpx.Response:
        upstream = httpx.MockTransport(lambda request: httpx.Response(200))
        client = AuthenticatedClient(transport=upstream, auth_manager=FakeAuthManager())
        try:
            return await client.get(f"https://{ALLOWED_HOST}/v2/profiles")
        finally:
            await client.aclose()

    async def scenario():
        ingest = RecordingIngestTransport()
        runtime = await build_runtime(tmp_path, ingest=ingest)
        set_metering_runtime(runtime)
        try:
            # Ordinary path: ToolAttributionMiddleware wraps a tool that
            # makes one metered call.
            middleware = ToolAttributionMiddleware()

            async def ordinary_call_next(context):
                return await make_one_metered_call()

            ordinary_ctx = SimpleNamespace(message=SimpleNamespace(name="search_profiles"))
            await middleware.on_call_tool(ordinary_ctx, ordinary_call_next)

            # Code Mode path: the bridge wraps the SAME kind of nested
            # call, via a stub sandbox, for the same tool name.
            async def bridged_call_tool_target(name, params):
                assert name == "search_profiles"
                return await make_one_metered_call()

            class _StubSandbox:
                async def run(self, code, *, inputs=None, external_functions=None):
                    return await external_functions["call_tool"]("search_profiles", {})

            provider = create_auth_bridging_sandbox_provider(_StubSandbox())
            ctx = _DummyContext()
            with patch("amazon_ads_mcp.server.code_mode.get_context", return_value=ctx):
                await provider.run(
                    "noop",
                    inputs={},
                    external_functions={"call_tool": bridged_call_tool_target},
                )

            events = await ingest.wait_for_event_count(2)
        finally:
            set_metering_runtime(None)
            await runtime.aclose()

        assert len(events) == 2
        tool_names = [e["data"]["dimensions"]["tool_name"] for e in events]
        assert tool_names == ["search_profiles", "search_profiles"]

    asyncio.run(scenario())
