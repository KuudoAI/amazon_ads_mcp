"""Round 3-A: integration test for PascalCase normalization in the live
middleware chain.

Tester observed that ``page_profiles({"Limit": 5, "Offset": 0})`` silently
returned successful with defaults — Pydantic ignored the extras and the
normalization middleware didn't appear to fire. This test reproduces the
case end-to-end.
"""

from __future__ import annotations


import pytest
from fastmcp import FastMCP


async def _make_server_with_paged_tool() -> FastMCP:
    from amazon_ads_mcp.middleware.error_envelope_middleware import (
        ErrorEnvelopeMiddleware,
    )
    from amazon_ads_mcp.middleware.schema_normalization import (
        SchemaKeyNormalizationMiddleware,
    )

    mcp = FastMCP("test-paged")
    mcp.add_middleware(ErrorEnvelopeMiddleware())
    mcp.add_middleware(SchemaKeyNormalizationMiddleware())

    @mcp.tool(name="page_profiles")
    async def page_profiles(
        offset: int = 0,
        limit: int = 10,
    ) -> dict:
        # Echo the values the function actually received so the test can
        # detect whether normalization rewrote PascalCase or it was silently
        # dropped to defaults.
        return {"offset": offset, "limit": limit}

    return mcp


async def _make_server_with_full_chain() -> FastMCP:
    """Same as ``_make_server_with_paged_tool`` but with the full middleware
    chain including ``MetaInjectionMiddleware`` so we can assert the
    success-path ``_meta.normalized`` telemetry surfaces to the agent."""
    from amazon_ads_mcp.middleware.error_envelope_middleware import (
        ErrorEnvelopeMiddleware,
    )
    from amazon_ads_mcp.middleware.meta_injection_middleware import (
        MetaInjectionMiddleware,
    )
    from amazon_ads_mcp.middleware.schema_normalization import (
        SchemaKeyNormalizationMiddleware,
    )

    mcp = FastMCP("test-paged-full")
    mcp.add_middleware(ErrorEnvelopeMiddleware())
    mcp.add_middleware(SchemaKeyNormalizationMiddleware())
    mcp.add_middleware(MetaInjectionMiddleware())

    @mcp.tool(name="page_profiles")
    async def page_profiles(offset: int = 0, limit: int = 10) -> dict:
        return {"offset": offset, "limit": limit, "items": []}

    return mcp


@pytest.mark.asyncio
async def test_pascal_case_inputs_get_rewritten_to_canonical_camel_case():
    """``Limit`` / ``Offset`` (PascalCase) must be rewritten to the
    canonical ``limit`` / ``offset`` before the tool function runs.
    Otherwise Pydantic silently ignores the extras and the call succeeds
    with defaults — which is the silent-acceptance failure mode the
    tester reported."""
    server = await _make_server_with_paged_tool()

    result = await server.call_tool("page_profiles", {"Limit": 5, "Offset": 3})
    payload = result.structured_content
    assert payload["limit"] == 5, (
        f"PascalCase Limit was silently dropped — got default {payload['limit']}"
    )
    assert payload["offset"] == 3


@pytest.mark.asyncio
async def test_successful_response_carries_meta_normalized_for_pascal_rewrite():
    """Round 3-A: when normalization rewrote keys, the agent must see
    ``_meta.normalized[]`` on the *successful* response. Otherwise the
    rewrite is silent and the agent never learns to use the canonical
    name on the next call."""
    server = await _make_server_with_full_chain()

    result = await server.call_tool("page_profiles", {"Limit": 5, "Offset": 3})
    payload = result.structured_content
    assert "_meta" in payload, (
        f"Success response missing _meta block. Payload: {payload}"
    )
    normalized_events = payload["_meta"].get("normalized") or []
    kinds = {e.get("kind") for e in normalized_events}
    # Must record the rename events so agents can self-correct
    assert "renamed" in kinds, f"missing 'renamed' event. events: {normalized_events}"
    rename_pairs = {(e["from"], e["to"]) for e in normalized_events if e.get("kind") == "renamed"}
    assert ("Limit", "limit") in rename_pairs
    assert ("Offset", "offset") in rename_pairs
