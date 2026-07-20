"""§8.3 "Main path": AuthenticatedClient's transport metering is
timing-independent (fix round 1, CRITICAL), through both construction
paths, and provider clients are never touched (Task 22 ruling #3,
controller boundary).

Fix round 1 changed the contract: `client._transport` (and every
populated `client._mounts` value) is now ALWAYS a `LazyMeteredTransport`,
regardless of whether a runtime is active at construction time -- the
actual metering decision is deferred to request time. These tests
therefore assert the STRUCTURAL wrap (always present) plus the BEHAVIORAL
outcome (event emitted iff a runtime is active at SEND time), rather than
asserting `client._transport` is directly a `MeteredAsyncTransport` at
construction time (see `test_construction_order_independence.py` for the
dedicated construction-vs-activation-order regression tests).
"""

from __future__ import annotations

import asyncio
import sys

import httpx
import pytest

pytestmark = pytest.mark.skipif(
    sys.version_info < (3, 12), reason="metering requires Python>=3.12"
)

if sys.version_info >= (3, 12):
    from amazon_ads_mcp.metering.adapter import (
        LazyMeteredTransport,
        get_metering_runtime,
        install_metered_transport,
        set_metering_runtime,
    )
    from amazon_ads_mcp.utils.http.client_manager import HTTPClientManager
    from amazon_ads_mcp.utils.http_client import AuthenticatedClient

    from ._support import ALLOWED_HOST, FakeAuthManager, RecordingIngestTransport, build_runtime


@pytest.fixture(autouse=True)
def _reset_metering_runtime():
    assert get_metering_runtime() is None
    yield
    set_metering_runtime(None)


def test_transport_is_always_lazy_wrapped_even_without_a_runtime() -> None:
    """Structural: the wrap is unconditional at construction time now --
    there is no "unwrapped" state for client._transport itself, only for
    what it delegates to at request time."""
    client = AuthenticatedClient()
    try:
        assert isinstance(client._transport, LazyMeteredTransport)
    finally:
        asyncio.run(client.aclose())


def test_no_active_runtime_behaves_unmetered(tmp_path) -> None:
    """Behavioral: with no active runtime, a request through the
    LazyMeteredTransport-wrapped client succeeds and emits nothing."""

    async def scenario():
        ingest = RecordingIngestTransport()
        upstream = httpx.MockTransport(lambda request: httpx.Response(200))
        client = AuthenticatedClient(transport=upstream, auth_manager=FakeAuthManager())
        try:
            response = await client.get(f"https://{ALLOWED_HOST}/v2/profiles")
            assert response.status_code == 200
        finally:
            await client.aclose()
        await asyncio.sleep(0.05)
        assert ingest.events() == []

    asyncio.run(scenario())


def test_active_runtime_wraps_direct_construction(tmp_path) -> None:
    async def scenario():
        ingest = RecordingIngestTransport()
        runtime = await build_runtime(tmp_path, ingest=ingest)
        set_metering_runtime(runtime)
        try:
            upstream = httpx.MockTransport(lambda request: httpx.Response(200))
            client = AuthenticatedClient(transport=upstream, auth_manager=FakeAuthManager())
            assert isinstance(client._transport, LazyMeteredTransport)
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


def test_active_runtime_wraps_http_client_manager_path(tmp_path) -> None:
    async def scenario():
        ingest = RecordingIngestTransport()
        runtime = await build_runtime(tmp_path, ingest=ingest)
        set_metering_runtime(runtime)
        manager = HTTPClientManager()
        try:
            client = await manager.get_client(
                client_class=AuthenticatedClient,
                transport=httpx.MockTransport(lambda request: httpx.Response(200)),
                auth_manager=FakeAuthManager(),
                base_url="https://advertising-api.amazon.com/unique-cache-key-1",
            )
            assert isinstance(client._transport, LazyMeteredTransport)

            response = await client.get(f"https://{ALLOWED_HOST}/v2/profiles")
            assert response.status_code == 200

            events = await ingest.wait_for_event_count(1)
            assert len(events) == 1
        finally:
            set_metering_runtime(None)
            await manager.close_all()
            await runtime.aclose()

    asyncio.run(scenario())


def test_mounts_stay_empty_without_proxy_env(tmp_path) -> None:
    """`_mounts` stays exactly what httpx set it to -- empty, since no
    construction path anywhere in this repo passes `mounts=` and no proxy
    env var is set here. See test_proxy_mounts.py for the populated-mounts
    case (fix round 1, IMPORTANT)."""

    async def scenario():
        runtime = await build_runtime(tmp_path)
        set_metering_runtime(runtime)
        try:
            client = AuthenticatedClient()
            try:
                assert client._mounts == {}
            finally:
                await client.aclose()
        finally:
            set_metering_runtime(None)
            await runtime.aclose()

    asyncio.run(scenario())


def test_plain_httpx_client_is_never_touched(tmp_path) -> None:
    """A plain httpx.AsyncClient (the shape every OAuth/OpenBridge/Kuudo
    provider client takes) is structurally unaffected by an active
    runtime -- install_metered_transport is never even called for it."""

    async def scenario():
        runtime = await build_runtime(tmp_path)
        set_metering_runtime(runtime)
        try:
            client = httpx.AsyncClient()
            try:
                assert not isinstance(client._transport, LazyMeteredTransport)
                assert isinstance(client._transport, httpx.AsyncHTTPTransport)
            finally:
                await client.aclose()
        finally:
            set_metering_runtime(None)
            await runtime.aclose()

    asyncio.run(scenario())


def test_install_metered_transport_always_wraps_in_lazy_metered_transport() -> None:
    """Fix round 1: install_metered_transport no longer short-circuits to
    `inner` unchanged when no runtime is active -- it always returns a
    LazyMeteredTransport, which itself defers the decision to request
    time (see test_no_active_runtime_behaves_unmetered above for the
    behavioral half of this contract)."""
    inner = httpx.AsyncHTTPTransport()
    try:
        wrapped = install_metered_transport(inner)
        assert isinstance(wrapped, LazyMeteredTransport)
        assert wrapped is not inner
    finally:
        asyncio.run(inner.aclose())
