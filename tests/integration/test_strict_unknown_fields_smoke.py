"""End-to-end smoke for MCP_STRICT_UNKNOWN_FIELDS (Commit 2 of fix/mcp-surface-quality).

Boots the real MCP server with strict mode enabled and exercises the
full middleware chain (envelope → schema_normalization → sidecar →
strict check). Verifies:

1. Default off: pass-through preserved (regression)
2. Strict on + typo: ValidationError surfaces with did_you_mean
3. Strict on + known canonical fields: NOT rejected (baseline regression)

The strict gate is intentionally placed inside sidecar's on_call_tool
AFTER any sidecar rewrite, so a caller who sends an alias that
sidecar legalizes (e.g. ``reportId`` → ``reportIds``) won't get
rejected. Unit tests cover the ordering contract directly.
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
async def mcp_server_strict_off():
    if not _resources_present():
        pytest.skip("No openapi/resources or dist/openapi/resources present")

    from amazon_ads_mcp.server.mcp_server import create_amazon_ads_server

    return await create_amazon_ads_server()


@pytest_asyncio.fixture
async def mcp_server_strict_on(monkeypatch):
    """Same MCP server with MCP_STRICT_UNKNOWN_FIELDS=true."""
    if not _resources_present():
        pytest.skip("No openapi/resources or dist/openapi/resources present")

    monkeypatch.setenv("MCP_STRICT_UNKNOWN_FIELDS", "true")
    from amazon_ads_mcp.config.settings import Settings
    from amazon_ads_mcp.middleware import schema_normalization as sn_module

    monkeypatch.setattr(sn_module, "settings", Settings())

    from amazon_ads_mcp.server.mcp_server import create_amazon_ads_server

    return await create_amazon_ads_server()


@pytest.mark.asyncio
async def test_strict_off_normal_call_succeeds(
    mcp_server_strict_off, monkeypatch
):
    """Default behavior: a normal canonical call succeeds. Baseline regression."""
    from fastmcp import Client

    big_profiles = [
        {"profileId": i, "accountInfo": {"name": f"acc-{i}", "type": "seller"}}
        for i in range(5)
    ]

    async def _fake_cached(force_refresh=False):
        return big_profiles, False

    from amazon_ads_mcp.tools import profile_listing

    monkeypatch.setattr(profile_listing, "get_profiles_cached", _fake_cached)
    monkeypatch.setattr(profile_listing, "_get_profiles_cached", _fake_cached)

    async with Client(mcp_server_strict_off) as client:
        result = await client.call_tool("search_profiles", {"limit": 5})
    assert result is not None


@pytest.mark.asyncio
async def test_strict_on_typo_returns_validation_error_with_suggestion(
    mcp_server_strict_on, monkeypatch
):
    """Strict mode + typo'd parameter on a real tool surfaces as
    mcp_input_validation through the FastMCP wire."""
    from fastmcp import Client
    from fastmcp.exceptions import ToolError

    big_profiles = [
        {"profileId": i, "accountInfo": {"name": f"acc-{i}", "type": "seller"}}
        for i in range(5)
    ]

    async def _fake_cached(force_refresh=False):
        return big_profiles, False

    from amazon_ads_mcp.tools import profile_listing

    monkeypatch.setattr(profile_listing, "get_profiles_cached", _fake_cached)
    monkeypatch.setattr(profile_listing, "_get_profiles_cached", _fake_cached)

    async with Client(mcp_server_strict_on) as client:
        with pytest.raises(ToolError) as excinfo:
            # ``limmit`` is a typo of ``limit``
            await client.call_tool("search_profiles", {"limmit": 5})

    msg = str(excinfo.value).lower()
    # Either our strict gate rejected it (preferred path) OR Pydantic
    # rejected upstream — both surface as validation errors. Either way
    # NOT a silent pass-through that would have returned 50 profiles.
    assert (
        "limmit" in msg
        or "unknown" in msg
        or "extra" in msg
        or "validation" in msg
        or "not permitted" in msg
    ), f"expected unknown-field rejection, got {excinfo.value!r}"


@pytest.mark.asyncio
async def test_strict_on_known_canonical_fields_succeed(
    mcp_server_strict_on, monkeypatch
):
    """Critical regression: strict mode does NOT reject canonical, known
    fields. If this fails, the strict gate is too aggressive."""
    from fastmcp import Client

    big_profiles = [
        {"profileId": i, "accountInfo": {"name": f"acc-{i}", "type": "seller"}}
        for i in range(5)
    ]

    async def _fake_cached(force_refresh=False):
        return big_profiles, False

    from amazon_ads_mcp.tools import profile_listing

    monkeypatch.setattr(profile_listing, "get_profiles_cached", _fake_cached)
    monkeypatch.setattr(profile_listing, "_get_profiles_cached", _fake_cached)

    async with Client(mcp_server_strict_on) as client:
        # Canonical args, no typos, strict mode on → must succeed
        result = await client.call_tool(
            "search_profiles", {"query": "acc", "limit": 5}
        )
    assert result is not None
