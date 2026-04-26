"""Phase 4 fix: Ads ``set_region`` must classify bad input as
``mcp_input_validation``, not ``internal_error``.

The current behavior (a bare ``ValueError`` from ``set_active_region``)
gets caught by the envelope translator's catch-all and bucketed as
``internal_error``. SP's equivalent tool returns a precise envelope with
hints naming the canonical regions; Ads should match.

Tests cover:
- Invalid region string → ``mcp_input_validation`` envelope
- Aliases like ``europe`` / ``usa`` → ``did_you_mean`` hint with the
  canonical code
- Empty / missing region → ``mcp_input_validation``
- Unknown garbage → ``mcp_input_validation`` with the canonical-values hint
"""

from __future__ import annotations

import json

import pytest
from fastmcp import FastMCP


async def _make_server() -> FastMCP:
    from amazon_ads_mcp.server.builtin_tools import register_region_tools
    from amazon_ads_mcp.middleware.error_envelope_middleware import (
        ErrorEnvelopeMiddleware,
    )

    mcp = FastMCP("test-set-region")
    mcp.add_middleware(ErrorEnvelopeMiddleware())
    await register_region_tools(mcp)
    return mcp


@pytest.mark.asyncio
async def test_invalid_region_string_classifies_as_mcp_input_validation():
    server = await _make_server()
    with pytest.raises(Exception) as exc_info:
        await server.call_tool("set_region", {"region": "antarctica"})
    envelope = json.loads(str(exc_info.value))
    assert envelope["error_kind"] == "mcp_input_validation"
    assert envelope["retryable"] is False
    assert envelope["_envelope_version"] == 1


@pytest.mark.asyncio
async def test_invalid_region_envelope_includes_canonical_values_hint():
    server = await _make_server()
    with pytest.raises(Exception) as exc_info:
        await server.call_tool("set_region", {"region": "antarctica"})
    envelope = json.loads(str(exc_info.value))
    hints_text = " ".join(envelope.get("hints", []))
    assert "na" in hints_text.lower()
    assert "eu" in hints_text.lower()
    assert "fe" in hints_text.lower()


@pytest.mark.asyncio
async def test_alias_europe_suggests_eu():
    server = await _make_server()
    with pytest.raises(Exception) as exc_info:
        await server.call_tool("set_region", {"region": "europe"})
    envelope = json.loads(str(exc_info.value))
    assert envelope["error_kind"] == "mcp_input_validation"
    hints_text = " ".join(envelope.get("hints", []))
    assert "eu" in hints_text.lower()


@pytest.mark.asyncio
async def test_alias_usa_suggests_na():
    server = await _make_server()
    with pytest.raises(Exception) as exc_info:
        await server.call_tool("set_region", {"region": "usa"})
    envelope = json.loads(str(exc_info.value))
    assert envelope["error_kind"] == "mcp_input_validation"
    hints_text = " ".join(envelope.get("hints", []))
    assert "na" in hints_text.lower()


@pytest.mark.asyncio
async def test_alias_apac_suggests_fe():
    server = await _make_server()
    with pytest.raises(Exception) as exc_info:
        await server.call_tool("set_region", {"region": "apac"})
    envelope = json.loads(str(exc_info.value))
    hints_text = " ".join(envelope.get("hints", []))
    assert "fe" in hints_text.lower()


@pytest.mark.asyncio
async def test_missing_region_classifies_as_mcp_input_validation():
    server = await _make_server()
    with pytest.raises(Exception) as exc_info:
        await server.call_tool("set_region", {})
    envelope = json.loads(str(exc_info.value))
    # Either the bare missing-arg case or our hand-validated one — both
    # must land in mcp_input_validation, not internal_error.
    assert envelope["error_kind"] == "mcp_input_validation"
