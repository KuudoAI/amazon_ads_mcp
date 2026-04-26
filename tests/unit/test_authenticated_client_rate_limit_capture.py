"""Round 4 #2: ``AuthenticatedClient.send`` must capture rate-limit
headers into the per-call context-var so OpenAPI-derived FastMCP tools
get ``_meta.rate_limit`` on success.

The tester reported that Ads success responses don't carry ``_meta``
even though ``MetaInjectionMiddleware`` is registered. Root cause: the
context-var is populated only by ``ResilientAuthenticatedClient.send``
(custom-tool path); FastMCP-from-OpenAPI tools route through
``AuthenticatedClient.send`` (the parent class), which doesn't capture.

Fix: capture in the parent class so every code path that calls ``send``
populates the context-var.
"""

from __future__ import annotations

import httpx
import pytest

from amazon_ads_mcp.utils.http.rate_limit_headers import (
    clear_last_http_meta,
    get_last_http_meta,
)


class _NoAuthClient:
    """Wrap ``AuthenticatedClient`` to skip the auth-injection step so the
    test isolates the rate-limit-capture concern from the auth pipeline.

    ``_inject_headers`` is a no-op override; everything else is the real
    parent ``send`` semantics.
    """

    @staticmethod
    def make(transport: httpx.MockTransport):
        from amazon_ads_mcp.utils.http_client import AuthenticatedClient

        client = AuthenticatedClient(
            auth_manager=None,
            media_registry=None,
            header_resolver=None,
            transport=transport,
        )

        async def _noop(_request):
            return None

        client._inject_headers = _noop  # type: ignore[method-assign]
        return client


@pytest.mark.asyncio
async def test_authenticated_client_send_captures_rate_limit_headers():
    """When the upstream response carries X-RateLimit-* headers, the
    parent ``AuthenticatedClient.send`` must populate the per-call
    context-var so the meta-injection middleware can surface them on
    success responses for OpenAPI-derived tools."""
    clear_last_http_meta()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={
                "X-RateLimit-Limit": "10",
                "X-RateLimit-Remaining": "3",
                "X-RateLimit-Reset": "1714074153",
            },
            json={"ok": True},
        )

    client = _NoAuthClient.make(httpx.MockTransport(handler))
    try:
        request = client.build_request("GET", "https://example.com/v2/profiles")
        response = await client.send(request)
        assert response.status_code == 200

        captured = get_last_http_meta()
        assert captured is not None, (
            "AuthenticatedClient.send must populate _LAST_HTTP_META so "
            "MetaInjectionMiddleware can surface _meta.rate_limit on "
            "success responses for OpenAPI-derived tools."
        )
        assert captured["rate_limit"]["limit_per_second"] == 10.0
        assert captured["rate_limit"]["remaining"] == 3.0
    finally:
        await client.aclose()
        clear_last_http_meta()


@pytest.mark.asyncio
async def test_authenticated_client_send_no_meta_when_headers_absent():
    """When upstream sends no rate-limit headers, the captured meta is
    falsy / empty — ``MetaInjectionMiddleware`` will skip injection."""
    clear_last_http_meta()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    client = _NoAuthClient.make(httpx.MockTransport(handler))
    try:
        request = client.build_request("GET", "https://example.com/v2/profiles")
        await client.send(request)
        captured = get_last_http_meta()
        assert not captured
    finally:
        await client.aclose()
        clear_last_http_meta()
