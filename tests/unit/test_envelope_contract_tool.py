"""Unit tests for the ``get_envelope_contract`` builtin tool.

Mirrors the SP server's contract probe. Returns metadata about the v1
cross-server error envelope this server implements: contract version,
supported error_kinds, normalized_kinds, env vars, and a spec URL.
"""

from __future__ import annotations

import pytest
from fastmcp import FastMCP


@pytest.mark.asyncio
async def test_envelope_contract_tool_returns_v1_metadata():
    from amazon_ads_mcp.server.builtin_tools import register_envelope_contract_tools
    from amazon_ads_mcp.middleware.error_envelope import (
        ENVELOPE_VERSION,
        SUPPORTED_ERROR_KINDS,
    )

    server = FastMCP("test-ads")
    await register_envelope_contract_tools(server)

    tool = await server.get_tool("get_envelope_contract")
    assert tool is not None, "get_envelope_contract should be registered"

    result = await tool.fn()
    assert result["contract_version"] == ENVELOPE_VERSION == 1
    assert set(result["error_kinds"]) == set(SUPPORTED_ERROR_KINDS)
    assert set(result["normalized_kinds"]) == {
        "renamed",
        "dropped_alias",
        "coerced",
        "unknown_field_passed_through",
        "unknown_field_rejected",
    }
    assert "MCP_SCHEMA_KEY_NORMALIZATION_ENABLED" in result["env_vars"]
    assert "MCP_SCHEMA_KEY_NORMALIZATION_META" in result["env_vars"]
    assert result["spec_url"].startswith("https://")


@pytest.mark.asyncio
async def test_envelope_contract_error_kinds_match_supported():
    """Tool's error_kinds list must be exactly SUPPORTED_ERROR_KINDS."""
    from amazon_ads_mcp.server.builtin_tools import register_envelope_contract_tools
    from amazon_ads_mcp.middleware.error_envelope import SUPPORTED_ERROR_KINDS

    server = FastMCP("test-ads")
    await register_envelope_contract_tools(server)
    tool = await server.get_tool("get_envelope_contract")
    result = await tool.fn()

    assert tuple(result["error_kinds"]) == tuple(SUPPORTED_ERROR_KINDS)
