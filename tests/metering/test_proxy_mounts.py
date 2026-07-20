"""Fix round 1, IMPORTANT: proxy mounts must not bypass the metering seam.

httpx auto-populates `AsyncClient._mounts` from `HTTP_PROXY`/`HTTPS_PROXY`/
`ALL_PROXY` env vars when `trust_env=True` (httpx's default, and nothing
in this repo overrides it -- verified: no construction path anywhere
passes `trust_env=False`). `Client._transport_for_url` checks `_mounts`
BEFORE falling back to `self._transport`, so a populated mount transport
completely bypasses whatever wraps `self._transport` alone. Fix:
`AuthenticatedClient.__init__` also wraps every populated `_mounts` value
with its own `LazyMeteredTransport`. `trust_env` itself is left
UNCHANGED (product behavior, not this task's to alter) -- proxied Amazon
Ads traffic gets metered (subject to the same host allowlist), other
proxied traffic passes through unmetered by policy, same as always.
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
        set_metering_runtime,
    )
    from amazon_ads_mcp.utils.http_client import AuthenticatedClient

    from ._support import ALLOWED_HOST, FakeAuthManager, RecordingIngestTransport, build_runtime


@pytest.fixture(autouse=True)
def _reset_metering_runtime():
    assert get_metering_runtime() is None
    yield
    set_metering_runtime(None)


def test_proxy_env_populates_mounts_wrapped_in_lazy_metered_transport(monkeypatch) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example.test:8080")

    client = AuthenticatedClient(auth_manager=FakeAuthManager())
    try:
        assert client._mounts, "expected HTTPS_PROXY to populate _mounts"
        for pattern, mount in client._mounts.items():
            assert mount is not None
            assert isinstance(mount, LazyMeteredTransport)
    finally:
        asyncio.run(client.aclose())


def test_amazon_host_request_via_proxy_mount_is_metered_when_active(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example.test:8080")

    async def scenario():
        ingest = RecordingIngestTransport()
        runtime = await build_runtime(tmp_path, ingest=ingest)
        set_metering_runtime(runtime)
        try:
            client = AuthenticatedClient(auth_manager=FakeAuthManager())
            assert client._mounts, "expected HTTPS_PROXY to populate _mounts"

            # Replace the proxy mount's inner transport with a mock so
            # the request never touches a real proxy/network -- white-box
            # on our own LazyMeteredTransport wrapping it.
            for pattern, mount in client._mounts.items():
                assert isinstance(mount, LazyMeteredTransport)
                mount._inner = httpx.MockTransport(lambda request: httpx.Response(200))

            try:
                response = await client.get(f"https://{ALLOWED_HOST}/v2/profiles")
                assert response.status_code == 200
            finally:
                await client.aclose()

            events = await ingest.wait_for_event_count(1)
            assert len(events) == 1
            assert events[0]["data"]["server.address"] == ALLOWED_HOST
        finally:
            set_metering_runtime(None)
            await runtime.aclose()

    asyncio.run(scenario())


def test_no_proxy_env_leaves_mounts_empty(monkeypatch) -> None:
    """Negative control: the ordinary case (no proxy env vars) still
    leaves `_mounts` empty, exactly as before this fix. Explicitly
    unsets every proxy var httpx's trust_env consults, rather than
    relying on the ambient shell happening not to have one set."""
    for var in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ):
        monkeypatch.delenv(var, raising=False)

    client = AuthenticatedClient(auth_manager=FakeAuthManager())
    try:
        assert client._mounts == {}
    finally:
        asyncio.run(client.aclose())
