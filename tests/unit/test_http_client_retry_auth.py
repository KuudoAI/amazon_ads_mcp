"""Retry scenarios must re-inject authentication headers.

Before this fix, ``AuthenticatedClient.send`` short-circuited on the
``auth_injected`` request extension, so a retry carried the *original*
Authorization header even when a background refresh had rotated the
access token. That defeated 401-triggered refresh-and-retry.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from amazon_ads_mcp.utils.http_client import AuthenticatedClient


@pytest.mark.asyncio
async def test_send_reinjects_on_each_call():
    auth_manager = MagicMock()
    auth_manager.get_headers = AsyncMock(
        side_effect=[
            {
                "Authorization": "Bearer token-v1",
                "Amazon-Advertising-API-ClientId": "cid",
            },
            {
                "Authorization": "Bearer token-v2",
                "Amazon-Advertising-API-ClientId": "cid",
            },
        ]
    )
    auth_manager.provider = MagicMock()
    # Default provider capability flags to "no" so the client does not
    # try to rewrite the URL based on identity-region routing.
    auth_manager.provider.requires_identity_region_routing = lambda: False
    auth_manager.get_active_identity = lambda: None

    client = AuthenticatedClient(auth_manager=auth_manager)

    captured: list[str] = []

    async def _fake_send(self, request: httpx.Request, **_kwargs) -> httpx.Response:  # noqa: ARG001
        captured.append(request.headers.get("authorization", ""))
        return httpx.Response(200)

    with patch.object(httpx.AsyncClient, "send", new=_fake_send):
        request1 = httpx.Request(
            "GET", "https://advertising-api.amazon.com/v2/profiles"
        )
        await client.send(request1)

        request2 = httpx.Request(
            "GET", "https://advertising-api.amazon.com/v2/profiles"
        )
        await client.send(request2)

    assert captured == ["Bearer token-v1", "Bearer token-v2"]
