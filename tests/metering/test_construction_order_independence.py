"""Fix round 1, CRITICAL: the metering wrap must be TIMING-INDEPENDENT.

Empirically reproduced by review: `create_amazon_ads_server()` builds the
shared `AuthenticatedClient` via `ServerBuilder.build()` BEFORE
`mcp.run()` ever triggers `server_lifespan()`, where `start_metering()`
actually runs. The original `install_metered_transport()` made a
ONE-SHOT decision at `__init__` time (`if get_metering_runtime() is None:
return inner unchanged`) -- for the shared client, that decision was made
while no runtime existed yet, and captured `runtime=None` PERMANENTLY:
the shared client (used for every OpenAPI-mounted tool call) would never
be metered in the real running server, no matter how long the server ran
afterward.

Fix: `LazyMeteredTransport` (`metering/adapter.py`) is now installed
UNCONDITIONALLY at `__init__` time, and defers the actual metering
decision to REQUEST time via `get_metering_runtime()` -- removing all
construction-order sensitivity. This module proves that directly, plus
drives the REAL boot order end-to-end (`ServerBuilder.build()` then
`server_lifespan()`, exactly as `create_amazon_ads_server()` +
`mcp.run()` would) as the most faithful reproduction of the reviewer's
finding.
"""

from __future__ import annotations

import asyncio
import sys
from types import SimpleNamespace

import httpx
import pytest

pytestmark = pytest.mark.skipif(
    sys.version_info < (3, 12), reason="metering requires Python>=3.12"
)

if sys.version_info >= (3, 12):
    from amazon_ads_mcp.metering.adapter import (
        LazyMeteredTransport,
        get_metering_runtime,
        set_metering_runtime,
    )
    from amazon_ads_mcp.utils.http_client import AuthenticatedClient

    from ._support import ALLOWED_HOST, FakeAuthManager, RecordingIngestTransport, build_runtime


@pytest.fixture(autouse=True)
def _reset_metering_runtime():
    assert get_metering_runtime() is None
    yield
    set_metering_runtime(None)


# -- (a) construct BEFORE start_metering, activate, THEN send -------------


def test_client_constructed_before_activation_still_gets_metered(tmp_path) -> None:
    async def scenario():
        ingest = RecordingIngestTransport()

        # Construct the client while NO runtime is active -- mirrors the
        # real boot order (ServerBuilder.build() runs before
        # server_lifespan()).
        assert get_metering_runtime() is None
        upstream = httpx.MockTransport(lambda request: httpx.Response(200))
        client = AuthenticatedClient(transport=upstream, auth_manager=FakeAuthManager())
        assert isinstance(client._transport, LazyMeteredTransport)

        # A request made before activation must succeed, unmetered.
        response = await client.get(f"https://{ALLOWED_HOST}/v2/profiles")
        assert response.status_code == 200
        await asyncio.sleep(0.05)
        assert ingest.events() == []

        # NOW metering activates (mirrors server_lifespan's
        # start_metering(), which runs after the client already exists).
        runtime = await build_runtime(tmp_path, ingest=ingest)
        set_metering_runtime(runtime)
        try:
            response = await client.get(f"https://{ALLOWED_HOST}/v2/campaigns")
            assert response.status_code == 200
            events = await ingest.wait_for_event_count(1)
            assert len(events) == 1
            assert events[0]["data"]["url.path"] == "/v2/campaigns"
        finally:
            await client.aclose()
            set_metering_runtime(None)
            await runtime.aclose()

    asyncio.run(scenario())


# -- (b) deactivate -> subsequent sends unmetered, no errors --------------


def test_deactivation_makes_subsequent_sends_unmetered_without_errors(tmp_path) -> None:
    async def scenario():
        ingest = RecordingIngestTransport()
        runtime = await build_runtime(tmp_path, ingest=ingest)
        set_metering_runtime(runtime)

        upstream = httpx.MockTransport(lambda request: httpx.Response(200))
        client = AuthenticatedClient(transport=upstream, auth_manager=FakeAuthManager())
        try:
            response = await client.get(f"https://{ALLOWED_HOST}/v2/profiles")
            assert response.status_code == 200
            events = await ingest.wait_for_event_count(1)
            assert len(events) == 1

            # Deactivate (mirrors server_lifespan's stop_metering()).
            set_metering_runtime(None)
            await runtime.aclose()

            # Subsequent sends on the SAME client object must succeed,
            # unmetered -- no errors, no new events.
            response = await client.get(f"https://{ALLOWED_HOST}/v2/campaigns")
            assert response.status_code == 200
            await asyncio.sleep(0.05)
            assert len(ingest.events()) == 1  # unchanged -- no new event
        finally:
            await client.aclose()

    asyncio.run(scenario())


# -- (c) existing activate-first behavior is unaffected --------------------


def test_activate_first_still_works(tmp_path) -> None:
    """Sanity: the ordinary (already-covered-elsewhere) activate-then-
    construct-then-send path still works under the new lazy design."""

    async def scenario():
        ingest = RecordingIngestTransport()
        runtime = await build_runtime(tmp_path, ingest=ingest)
        set_metering_runtime(runtime)
        try:
            upstream = httpx.MockTransport(lambda request: httpx.Response(200))
            client = AuthenticatedClient(transport=upstream, auth_manager=FakeAuthManager())
            try:
                response = await client.get(f"https://{ALLOWED_HOST}/v2/profiles")
                assert response.status_code == 200
            finally:
                await client.aclose()

            events = await ingest.wait_for_event_count(1)
            assert len(events) == 1
        finally:
            set_metering_runtime(None)
            await runtime.aclose()

    asyncio.run(scenario())


# -- the reviewer's literal reproduction: real ServerBuilder + lifespan ---


def test_real_boot_order_shared_client_becomes_metered_once_lifespan_starts(
    tmp_path, monkeypatch
) -> None:
    """Drives the REAL boot order: ServerBuilder.build() constructs the
    shared client (the exact call create_amazon_ads_server() makes)
    BEFORE server_lifespan() (the exact function passed to FastMCP's
    lifespan=) ever runs. Only the shared client's innermost transport is
    swapped for a MockTransport post-construction (avoiding a real
    network call) -- everything else is the real construction path.
    """
    from amazon_ads_mcp.server import mcp_server
    from amazon_ads_mcp.server.mcp_server import server_lifespan
    from amazon_ads_mcp.server.server_builder import ServerBuilder

    from ._support import CONFIG_PATH, base_env

    monkeypatch.setattr(mcp_server, "_cleanup_done", False)

    env = base_env(tmp_path)
    env["METERING_CONFIG"] = str(CONFIG_PATH)
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    async def scenario():
        # Step 1: build the server -- this is exactly what
        # create_amazon_ads_server() does, and it runs BEFORE lifespan.
        builder = ServerBuilder(lifespan=server_lifespan)
        await builder.build()
        shared_client = builder.client
        assert isinstance(shared_client, AuthenticatedClient)
        assert isinstance(shared_client._transport, LazyMeteredTransport)
        assert get_metering_runtime() is None  # lifespan hasn't run yet

        # Swap the shared client's innermost transport for a mock so the
        # test never touches the real network -- white-box on our OWN
        # LazyMeteredTransport, not on httpx internals.
        recorded = {"calls": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            recorded["calls"] += 1
            return httpx.Response(200)

        shared_client._transport._inner = httpx.MockTransport(handler)
        shared_client.auth_manager = FakeAuthManager()

        # Step 2: NOW the lifespan runs (mirrors mcp.run() triggering it
        # after build() already returned) -- this is where
        # start_metering() actually activates a runtime.
        async with server_lifespan(SimpleNamespace()):
            assert get_metering_runtime() is not None

            response = await shared_client.get(f"https://{ALLOWED_HOST}/v2/profiles")
            assert response.status_code == 200
            assert recorded["calls"] == 1

            runtime = get_metering_runtime()
            # health().transports aggregates stats from every transport
            # this runtime has wrapped -- a nonzero attempt_count here
            # proves the SHARED (pre-lifespan-built) client's request was
            # genuinely metered, not merely unbroken.
            health = runtime.health()
            assert health["transports"]["attempt_count"] >= 1

        assert get_metering_runtime() is None
        await shared_client.aclose()

    asyncio.run(scenario())
