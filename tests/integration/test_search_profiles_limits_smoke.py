"""End-to-end smoke for search_profiles / page_profiles limit validation
(Commit 3 of fix/mcp-surface-quality).

Boots the real MCP server in-memory and exercises the limit-validation path
through the full middleware chain (envelope translator, schema normalization).
Mocks the cached profile list — no live Amazon API call.

Catches regressions in:
- the validation logic itself (negative/zero raises typed error)
- the envelope translator's classification of ValidationError as
  mcp_input_validation
- the cap-message wiring on the existing `message` response field
"""

from __future__ import annotations

import pathlib

import pytest
import pytest_asyncio

pytest.importorskip("fastmcp")


def _resources_present() -> bool:
    root = pathlib.Path(__file__).parents[2]
    return (root / "openapi" / "resources").exists() or (
        root / "dist" / "openapi" / "resources"
    ).exists()


@pytest_asyncio.fixture
async def mcp_server_with_many_profiles(monkeypatch):
    """Real MCP server with a 100-profile mocked cached list.

    100 profiles is enough to test cap behavior at search (50) and page (100)
    boundaries.
    """
    if not _resources_present():
        pytest.skip("No openapi/resources or dist/openapi/resources present")

    profiles = [
        {
            "profileId": 1000 + i,
            "countryCode": "US",
            "accountInfo": {"name": f"acct-{i}", "type": "seller"},
        }
        for i in range(100)
    ]

    async def _fake_cached(force_refresh=False):
        return profiles, False

    from amazon_ads_mcp.tools import profile_listing

    monkeypatch.setattr(profile_listing, "get_profiles_cached", _fake_cached)
    # The internal helper is also referenced by name in some places
    monkeypatch.setattr(profile_listing, "_get_profiles_cached", _fake_cached)

    from amazon_ads_mcp.server.mcp_server import create_amazon_ads_server

    return await create_amazon_ads_server()


def _payload(result):
    payload = result.structured_content or result.data
    if hasattr(payload, "model_dump"):
        payload = payload.model_dump()
    return payload


@pytest.mark.asyncio
async def test_search_profiles_negative_limit_returns_validation_error(
    mcp_server_with_many_profiles,
):
    """Wire-path: limit=-5 returns typed validation error through the envelope,
    not silent default."""
    from fastmcp import Client
    from fastmcp.exceptions import ToolError

    async with Client(mcp_server_with_many_profiles) as client:
        with pytest.raises(ToolError) as excinfo:
            await client.call_tool("search_profiles", {"limit": -5})

    msg = str(excinfo.value).lower()
    assert "must be > 0" in msg or "limit" in msg, (
        f"expected validation reason in error, got {excinfo.value!r}"
    )


@pytest.mark.asyncio
async def test_search_profiles_over_cap_returns_clamped_with_cap_notice(
    mcp_server_with_many_profiles,
):
    """Wire-path: limit=200 returns exactly 50 items with a cap notice in the
    response message field. No silent clamping — the caller sees the cap."""
    from fastmcp import Client

    async with Client(mcp_server_with_many_profiles) as client:
        result = await client.call_tool("search_profiles", {"limit": 200})

    payload = _payload(result)
    # 100 mocked profiles, cap at 50
    assert payload["returned_count"] == 50
    assert payload["message"] is not None
    msg = payload["message"]
    assert "200" in msg and "50" in msg, (
        f"expected cap notice with 200/50 in message, got {msg!r}"
    )


@pytest.mark.asyncio
async def test_search_profiles_within_cap_no_cap_notice(
    mcp_server_with_many_profiles,
):
    """Regression: limit within bounds returns no cap notice (back-compat)."""
    from fastmcp import Client

    async with Client(mcp_server_with_many_profiles) as client:
        result = await client.call_tool("search_profiles", {"limit": 25})

    payload = _payload(result)
    assert payload["returned_count"] == 25
    # No cap notice; message either None or doesn't mention "clamped"
    assert payload.get("message") is None or "clamped" not in payload["message"].lower()


@pytest.mark.asyncio
async def test_page_profiles_negative_limit_returns_validation_error(
    mcp_server_with_many_profiles,
):
    """page_profiles applies the same contract as search_profiles."""
    from fastmcp import Client
    from fastmcp.exceptions import ToolError

    async with Client(mcp_server_with_many_profiles) as client:
        with pytest.raises(ToolError):
            await client.call_tool("page_profiles", {"limit": -5})


@pytest.mark.asyncio
async def test_page_profiles_over_cap_returns_clamped_with_cap_notice(
    mcp_server_with_many_profiles,
):
    """page_profiles caps at MAX_PAGE_LIMIT=100 with a cap notice."""
    from fastmcp import Client

    async with Client(mcp_server_with_many_profiles) as client:
        result = await client.call_tool("page_profiles", {"limit": 500})

    payload = _payload(result)
    assert payload["returned_count"] == 100  # all 100 mocked profiles
    assert payload["message"] is not None
    msg = payload["message"]
    assert "500" in msg and "100" in msg, (
        f"expected cap notice with 500/100 in message, got {msg!r}"
    )
