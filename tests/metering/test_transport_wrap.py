"""§8.3 "Main path": AuthenticatedClient's transport is wrapped IFF a
metering runtime is active, through both construction paths, and provider
clients are never touched (Task 22 rulings #3, controller boundary).
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
    from mcp_outbound_metering.transport import MeteredAsyncTransport

    from amazon_ads_mcp.metering.adapter import (
        get_metering_runtime,
        install_metered_transport,
        set_metering_runtime,
    )
    from amazon_ads_mcp.utils.http_client import AuthenticatedClient
    from amazon_ads_mcp.utils.http.client_manager import HTTPClientManager

    from ._support import build_runtime


@pytest.fixture(autouse=True)
def _reset_metering_runtime():
    assert get_metering_runtime() is None
    yield
    set_metering_runtime(None)


def test_no_active_runtime_leaves_transport_unwrapped(tmp_path) -> None:
    client = AuthenticatedClient()
    try:
        assert not isinstance(client._transport, MeteredAsyncTransport)
        assert isinstance(client._transport, httpx.AsyncHTTPTransport)
    finally:
        asyncio.run(client.aclose())


def test_active_runtime_wraps_direct_construction(tmp_path) -> None:
    async def scenario():
        runtime = await build_runtime(tmp_path)
        set_metering_runtime(runtime)
        try:
            client = AuthenticatedClient()
            try:
                assert isinstance(client._transport, MeteredAsyncTransport)
            finally:
                await client.aclose()
        finally:
            set_metering_runtime(None)
            await runtime.aclose()

    asyncio.run(scenario())


def test_active_runtime_wraps_http_client_manager_path(tmp_path) -> None:
    async def scenario():
        runtime = await build_runtime(tmp_path)
        set_metering_runtime(runtime)
        manager = HTTPClientManager()
        try:
            client = await manager.get_client(
                client_class=AuthenticatedClient,
                base_url="https://advertising-api.amazon.com/unique-cache-key-1",
            )
            assert isinstance(client._transport, MeteredAsyncTransport)
        finally:
            set_metering_runtime(None)
            await manager.close_all()
            await runtime.aclose()

    asyncio.run(scenario())


def test_mounts_are_never_wrapped(tmp_path) -> None:
    """`_mounts` stays exactly what httpx set it to (empty, since no
    construction path anywhere in this repo passes `mounts=`) --
    `install_metered_transport` only ever touches the single transport
    instance handed to it, never `_mounts`."""

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
                assert not isinstance(client._transport, MeteredAsyncTransport)
            finally:
                await client.aclose()
        finally:
            set_metering_runtime(None)
            await runtime.aclose()

    asyncio.run(scenario())


def test_install_metered_transport_is_pure_pass_through_without_runtime() -> None:
    inner = httpx.AsyncHTTPTransport()
    try:
        assert install_metered_transport(inner) is inner
    finally:
        asyncio.run(inner.aclose())
