"""§8.3 "OAuth exclusion": each provider's `_get_client()` yields an
unwrapped plain client even with an active metering runtime (Task 22
boundary requirement -- OAuth/OpenBridge/Kuudo provider clients are
structurally unmetered and must never be touched).

Verified repo facts: `DirectAmazonAdsProvider._get_client()` and
`OpenBridgeAuthProvider._get_client()` both return
`utils.http.get_http_client()` with `authenticated` defaulting to
`False`, which routes to `HTTPClientManager.get_client()` with NO
`client_class` -- i.e. a plain `httpx.AsyncClient`, never
`AuthenticatedClient`. `KuudoAuthProvider._get_client()` constructs a
plain `httpx.AsyncClient(...)` directly. None of the three ever passes
through `AuthenticatedClient.__init__` (the ONE seam that calls
`install_metered_transport`), so an active runtime can structurally never
reach them -- this test proves that boundary holds for all three.
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

    from amazon_ads_mcp.metering.adapter import set_metering_runtime

    from ._support import build_runtime


@pytest.fixture
def _active_runtime(tmp_path):
    async def _build():
        return await build_runtime(tmp_path)

    runtime = asyncio.run(_build())
    set_metering_runtime(runtime)
    try:
        yield runtime
    finally:
        set_metering_runtime(None)
        asyncio.run(runtime.aclose())


def _assert_unwrapped(client: httpx.AsyncClient) -> None:
    assert type(client) is httpx.AsyncClient
    assert not isinstance(client._transport, MeteredAsyncTransport)


def test_direct_provider_get_client_is_unwrapped(_active_runtime) -> None:
    from amazon_ads_mcp.auth.base import ProviderConfig
    from amazon_ads_mcp.auth.providers.direct import DirectAmazonAdsProvider

    provider = DirectAmazonAdsProvider(
        ProviderConfig(
            client_id="test-client-id",
            client_secret="test-client-secret",
            refresh_token="test-refresh-token",
        )
    )

    async def scenario():
        client = await provider._get_client()
        _assert_unwrapped(client)

    asyncio.run(scenario())


def test_openbridge_provider_get_client_is_unwrapped(_active_runtime) -> None:
    from amazon_ads_mcp.auth.base import ProviderConfig
    from amazon_ads_mcp.auth.providers.openbridge import OpenBridgeProvider

    provider = OpenBridgeProvider(ProviderConfig(refresh_token="test-openbridge-token"))

    async def scenario():
        client = await provider._get_client()
        _assert_unwrapped(client)

    asyncio.run(scenario())


def test_kuudo_provider_get_client_is_unwrapped(_active_runtime) -> None:
    from amazon_ads_mcp.auth.base import ProviderConfig
    from amazon_ads_mcp.auth.providers.kuudo import KuudoAmazonAdsProvider

    provider = KuudoAmazonAdsProvider(
        ProviderConfig(
            base_url="https://app.kuudo.test",
            api_key="sk_test",
            provider="amazon_ads",
        )
    )

    async def scenario():
        client = await provider._get_client()
        # Kuudo builds a raw httpx.AsyncClient directly (no
        # get_http_client() indirection) -- same assertion, different
        # construction path.
        _assert_unwrapped(client)
        await client.aclose()

    asyncio.run(scenario())
