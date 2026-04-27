"""Unit tests for client accept header resolution.

This module tests the accept header resolution functionality
in the authenticated client for different API endpoints.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from amazon_ads_mcp.auth.base import BaseAmazonAdsProvider
from amazon_ads_mcp.auth.manager import AuthManager
from amazon_ads_mcp.utils.http_client import AuthenticatedClient
from amazon_ads_mcp.utils.media import MediaTypeRegistry


def _build_direct_auth_manager(headers=None):
    """Spec'd AuthManager + provider for accept-resolver tests.

    Both manager and provider are spec'd so attribute typos and API renames
    fail at test time. Defaults match a non-routing direct provider.
    """
    manager = MagicMock(spec=AuthManager)
    manager.get_headers = AsyncMock(
        return_value=headers or {"Authorization": "Bearer test"}
    )
    manager.provider = MagicMock(spec=BaseAmazonAdsProvider)
    manager.provider.requires_identity_region_routing = MagicMock(return_value=False)
    manager.provider.headers_are_identity_specific = MagicMock(return_value=False)
    manager.provider.region_controlled_by_identity = MagicMock(return_value=False)
    manager.provider.provider_type = "direct"
    manager.get_active_identity = MagicMock(return_value=None)
    return manager


@pytest.mark.asyncio
async def test_authenticated_client_sets_accept_for_exports(monkeypatch):
    captured = {}

    async def fake_send(self, request: httpx.Request, **kwargs):
        captured["accept"] = request.headers.get("Accept")
        return httpx.Response(200, request=request)

    monkeypatch.setattr(httpx.AsyncClient, "send", fake_send, raising=True)

    async with AuthenticatedClient() as c:
        await c.get("https://api.example.com/exports/ABC123")

    # Expect a vendor-type Accept (from override heuristic)
    assert captured.get("accept", "").startswith("application/")


@pytest.mark.asyncio
async def test_explicit_accept_header_is_respected(monkeypatch):
    captured = {}

    async def fake_send(self, request: httpx.Request, **kwargs):
        captured["accept"] = request.headers.get("Accept")
        return httpx.Response(200, request=request)

    monkeypatch.setattr(httpx.AsyncClient, "send", fake_send, raising=True)

    async with AuthenticatedClient() as c:
        req = c.build_request(
            "GET",
            "https://api.example.com/exports/ABC123",
            headers={"Accept": "text/vnd.measurementresult.v1.2+csv"},
        )
        await c.send(req)

    assert captured.get("accept") == "text/vnd.measurementresult.v1.2+csv"


@pytest.mark.asyncio
async def test_httpx_default_accept_is_overridden_with_vendored_type():
    """Regression: httpx defaults Accept to "*/*"; the media registry's
    vendored Accept must replace it. Previously the "Accept not in headers"
    guard treated "*/*" as caller-set and skipped the override, causing
    HTTP 415 on Sponsored Products v3 and Target Promotion Groups v1
    endpoints.
    """
    auth_manager = _build_direct_auth_manager()

    registry = MagicMock(spec=MediaTypeRegistry)
    registry.resolve = MagicMock(
        return_value=(
            "application/vnd.spCampaign.v3+json",
            ["application/vnd.spCampaign.v3+json"],
        )
    )

    client = AuthenticatedClient(
        auth_manager=auth_manager,
        media_registry=registry,
    )

    # Build a request via the client itself so httpx's default
    # Accept: */* is present, mirroring the real upstream call path.
    request = client.build_request(
        "POST",
        "https://advertising-api-eu.amazon.com/sp/campaigns/list",
        json={"stateFilter": {"include": ["ENABLED"]}},
    )
    assert request.headers.get("accept") == "*/*"

    with patch.object(httpx.AsyncClient, "send", autospec=True) as mock_send:
        mock_send.return_value = httpx.Response(200, request=request)
        await client.send(request)

    # autospec=True on bound method: call_args[0][0] is `self`, [1] is the request.
    sent = mock_send.call_args[0][1]
    assert sent.headers.get("accept") == "application/vnd.spCampaign.v3+json"
    assert (
        sent.headers.get("content-type") == "application/vnd.spCampaign.v3+json"
    )


@pytest.mark.asyncio
async def test_explicit_vendored_accept_is_preserved():
    """Callers pinning a specific vendored Accept (e.g. TPG v2) must not
    be overridden by the registry's first-listed vendored type.
    """
    auth_manager = _build_direct_auth_manager()

    registry = MagicMock(spec=MediaTypeRegistry)
    registry.resolve = MagicMock(
        return_value=(
            "application/vnd.sptargetpromotiongroup.v1+json",
            [
                "application/vnd.sptargetpromotiongroup.v1+json",
                "application/vnd.sptargetpromotiongroup.v2+json",
            ],
        )
    )

    client = AuthenticatedClient(
        auth_manager=auth_manager,
        media_registry=registry,
    )

    request = client.build_request(
        "POST",
        "https://advertising-api-eu.amazon.com/sp/targetPromotionGroups",
        headers={"Accept": "application/vnd.sptargetpromotiongroup.v2+json"},
        json={},
    )

    with patch.object(httpx.AsyncClient, "send", autospec=True) as mock_send:
        mock_send.return_value = httpx.Response(200, request=request)
        await client.send(request)

    # autospec=True on bound method: call_args[0][0] is `self`, [1] is the request.
    sent = mock_send.call_args[0][1]
    assert (
        sent.headers.get("accept")
        == "application/vnd.sptargetpromotiongroup.v2+json"
    )
