"""End-to-end smoke for R2 — per-ad-product cap validator (SPONSORED_PRODUCTS=1000).

Registers a test-only tool whose name ends with ``QueryCampaign`` (the
suffix the cap validator targets) on the real MCP server, then exercises
the validator through the full middleware chain (envelope →
schema_normalization → sidecar → R1 schema constraints → R2 ad-product
caps → tool dispatch). Captures the wire envelope shape on the FastMCP
Client side.

The real Amazon ``allv1_QueryCampaign`` may or may not be mounted in
the test env (depends on whether ``openapi/resources/`` is present and
which auth provider is active). Using a test tool with the matching
suffix gives us deterministic wire coverage regardless.

Two critical wire-path assertions:

1. SPONSORED_PRODUCTS with maxResults > 1000 raises
   ``mcp_input_validation`` LOCALLY — the bad call never reaches the
   tool implementation.
2. SPONSORED_BRANDS at the schema's max=5000 does NOT get rejected by
   the cap validator — fail-open contract preserved through the wire.
"""

from __future__ import annotations

import pathlib

import pytest
import pytest_asyncio
from pydantic import BaseModel, Field

pytest.importorskip("fastmcp")


def _resources_present() -> bool:
    root = pathlib.Path(__file__).parents[2]
    return (root / "openapi" / "resources").exists() or (
        root / "dist" / "openapi" / "resources"
    ).exists()


class _AdProductFilterModel(BaseModel):
    """Mirror of CampaignAdProductFilter for the test tool's input schema."""

    include: list[str] = Field(default_factory=list, max_length=1, min_length=1)


@pytest_asyncio.fixture
async def mcp_server_with_test_query_campaign():
    """Real MCP server with a test-only ``test_QueryCampaign`` tool
    that matches the per-ad-product cap validator's suffix targets."""
    if not _resources_present():
        pytest.skip("No openapi/resources or dist/openapi/resources present")

    from amazon_ads_mcp.server.mcp_server import create_amazon_ads_server

    server = await create_amazon_ads_server()

    @server.tool(name="test_QueryCampaign")
    async def test_query_campaign(
        adProductFilter: _AdProductFilterModel,
        maxResults: int = Field(100, ge=1, le=5000),
    ) -> dict:
        return {
            "received": True,
            "ad_product": adProductFilter.include[0]
            if adProductFilter.include
            else None,
            "max_results": maxResults,
        }

    return server


@pytest.mark.asyncio
async def test_sponsored_products_over_cap_rejected_on_wire(
    mcp_server_with_test_query_campaign,
):
    """Headline R2 fix: SPONSORED_PRODUCTS with maxResults > 1000
    raises locally with mcp_input_validation. Error message references
    ad product, cap, and requested value."""
    from fastmcp import Client
    from fastmcp.exceptions import ToolError

    async with Client(mcp_server_with_test_query_campaign) as client:
        with pytest.raises(ToolError) as excinfo:
            await client.call_tool(
                "test_QueryCampaign",
                {
                    "adProductFilter": {"include": ["SPONSORED_PRODUCTS"]},
                    "maxResults": 1500,
                },
            )

    msg = str(excinfo.value)
    assert "SPONSORED_PRODUCTS" in msg, (
        f"expected ad product in error, got {msg!r}"
    )
    assert "1000" in msg
    assert "1500" in msg


@pytest.mark.asyncio
async def test_sponsored_products_at_cap_passes_validator(
    mcp_server_with_test_query_campaign,
):
    """maxResults=1000 (exactly at SP cap) must NOT be rejected — the
    tool is reached and returns its normal response shape."""
    from fastmcp import Client

    async with Client(mcp_server_with_test_query_campaign) as client:
        result = await client.call_tool(
            "test_QueryCampaign",
            {
                "adProductFilter": {"include": ["SPONSORED_PRODUCTS"]},
                "maxResults": 1000,
            },
        )

    payload = result.structured_content or result.data
    if hasattr(payload, "model_dump"):
        payload = payload.model_dump()
    assert payload.get("received") is True
    assert payload.get("max_results") == 1000


@pytest.mark.asyncio
async def test_sponsored_brands_at_schema_max_fails_open_through_wire(
    mcp_server_with_test_query_campaign,
):
    """SPONSORED_BRANDS has no confirmed cap → fail-open. maxResults
    at the schema's max=5000 must NOT be rejected by the per-ad-product
    cap validator. R1's schema check (max=5000) is the only upper bound
    for this ad product."""
    from fastmcp import Client

    async with Client(mcp_server_with_test_query_campaign) as client:
        result = await client.call_tool(
            "test_QueryCampaign",
            {
                "adProductFilter": {"include": ["SPONSORED_BRANDS"]},
                "maxResults": 5000,
            },
        )

    payload = result.structured_content or result.data
    if hasattr(payload, "model_dump"):
        payload = payload.model_dump()
    assert payload.get("received") is True
    assert payload.get("max_results") == 5000


@pytest.mark.asyncio
async def test_sponsored_brands_above_schema_max_caught_by_r1(
    mcp_server_with_test_query_campaign,
):
    """SPONSORED_BRANDS with maxResults=5001 (above schema max=5000) must
    be caught — by R1's schema-constraint check, not R2. Confirms the
    two checks compose correctly when the unknown-cap fail-open of R2
    falls back to the schema's hard ceiling."""
    from fastmcp import Client
    from fastmcp.exceptions import ToolError

    async with Client(mcp_server_with_test_query_campaign) as client:
        with pytest.raises(ToolError) as excinfo:
            await client.call_tool(
                "test_QueryCampaign",
                {
                    "adProductFilter": {"include": ["SPONSORED_BRANDS"]},
                    "maxResults": 5001,
                },
            )

    msg = str(excinfo.value).lower()
    # Either R1 or pydantic rejects (5001 > schema max=5000)
    assert "5000" in msg or "validation" in msg or "5001" in msg or "less" in msg, (
        f"expected validation error for over-schema-max, got {excinfo.value!r}"
    )


@pytest.mark.asyncio
async def test_opt_out_disables_cap_validator_on_wire(
    monkeypatch, mcp_server_with_test_query_campaign
):
    """MCP_AD_PRODUCT_CAP_VALIDATION_ENABLED=false → over-cap calls pass
    through (R1's schema check would still allow up to 5000, so the
    test tool sees the overshoot value)."""
    monkeypatch.setenv("MCP_AD_PRODUCT_CAP_VALIDATION_ENABLED", "false")
    from amazon_ads_mcp.config.settings import Settings
    from amazon_ads_mcp.middleware import schema_normalization as sn_module

    monkeypatch.setattr(sn_module, "settings", Settings())

    from fastmcp import Client

    async with Client(mcp_server_with_test_query_campaign) as client:
        result = await client.call_tool(
            "test_QueryCampaign",
            {
                "adProductFilter": {"include": ["SPONSORED_PRODUCTS"]},
                "maxResults": 1500,
            },
        )

    payload = result.structured_content or result.data
    if hasattr(payload, "model_dump"):
        payload = payload.model_dump()
    assert payload.get("received") is True
    assert payload.get("max_results") == 1500
