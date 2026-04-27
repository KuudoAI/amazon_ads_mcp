"""Unit tests for the Ads schema-driven pre-flight key normalization layer.

The module under test, ``amazon_ads_mcp.middleware.schema_normalization``,
implements the v1 cross-server contract's schema-driven key normalization
described in ``openbridge-mcp/CONTRACT.md``. It is independent of the
declarative aliasing in ``server/sidecar_middleware.py`` (which handles
operation-specific overlays like ``reportId`` → ``reportIds``).

Behavior contract:

- Unique schema match → rewrite to canonical key
- Ambiguous match → unchanged (passes through; emits ``unknown_field_passed_through``)
- No match → unchanged (passes through; emits ``unknown_field_passed_through``)
- Canonical present alongside alias → drop alias (emits ``dropped_alias``)
- Schema is array-typed but client provided scalar → wrap to single-item list
  (emits ``coerced``)

Tests use FastMCP's tool registration to provide schema; no declarative
sidecar overlay files are needed.
"""

from __future__ import annotations

from typing import List, Optional

import pytest
from fastmcp import FastMCP
from pydantic import Field


# ---------------------------------------------------------------------------
# Helpers — register tools with known schemas
# ---------------------------------------------------------------------------


async def _register_canonical_tool(server: FastMCP) -> None:
    @server.tool(name="adsv1_list_campaigns")
    async def list_campaigns(
        marketplaceIds: List[str] = Field(default_factory=list),
        campaignId: Optional[str] = None,
        orderStatuses: Optional[List[str]] = None,
    ) -> dict:
        return {
            "marketplaceIds": marketplaceIds,
            "campaignId": campaignId,
            "orderStatuses": orderStatuses,
        }


def _ambiguous_schema_properties() -> dict:
    """Build a schema-properties dict where two keys normalize to the same token.

    FastMCP/Pydantic cannot express two Python parameters that differ only in
    casing or punctuation, so this helper feeds the internal normalizer
    directly. The resulting schema mimics what an OpenAPI document with
    ``user_id`` and ``userId`` (both → ``userid``) would produce.
    """
    return {
        "user_id": {"type": "string"},
        "userId": {"type": "string"},
        "campaignId": {"type": "string"},
    }


# ---------------------------------------------------------------------------
# Module surface
# ---------------------------------------------------------------------------


def test_module_exposes_rewrite_args_and_middleware():
    from amazon_ads_mcp.middleware import schema_normalization as mod

    assert hasattr(mod, "rewrite_args")
    assert hasattr(mod, "SchemaKeyNormalizationMiddleware")


# ---------------------------------------------------------------------------
# Pure rewrite_args function (no MCP context required)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unique_match_rewrite_pascal_to_camel():
    from amazon_ads_mcp.middleware.schema_normalization import rewrite_args

    server = FastMCP("test")
    await _register_canonical_tool(server)

    args = {"MarketplaceIds": ["ATVPDKIKX0DER"]}
    rewritten, events = await rewrite_args("adsv1_list_campaigns", args, server=server)

    assert rewritten == {"marketplaceIds": ["ATVPDKIKX0DER"]}
    assert events == [
        {
            "kind": "renamed",
            "from": "MarketplaceIds",
            "to": "marketplaceIds",
            "reason": "schema_canonical_key",
        }
    ]


@pytest.mark.asyncio
async def test_no_match_passes_through_with_event(monkeypatch):
    """Round 12 follow-up: with strict-unknown ON (default), the event
    kind is ``unknown_field_rejected``. The original
    ``unknown_field_passed_through`` only fires when the flag is off —
    covered by the parallel test below."""
    from amazon_ads_mcp.middleware.schema_normalization import rewrite_args

    server = FastMCP("test")
    await _register_canonical_tool(server)

    args = {"unknownField": "x"}
    rewritten, events = await rewrite_args("adsv1_list_campaigns", args, server=server)

    # Schema-key normalization itself does not drop the field — the
    # downstream SchemaValidationMiddleware does the rejection.
    assert rewritten == {"unknownField": "x"}
    assert events == [
        {
            "kind": "unknown_field_rejected",
            "field": "unknownField",
            "reason": "no_schema_match",
        }
    ]


@pytest.mark.asyncio
async def test_no_match_emits_passed_through_when_strict_off(monkeypatch):
    """When MCP_STRICT_UNKNOWN_FIELDS=false, the event kind retains the
    original ``unknown_field_passed_through`` label because the field
    really is forwarded to the upstream API."""
    from amazon_ads_mcp.middleware import schema_normalization as sn_mod
    from amazon_ads_mcp.middleware.schema_normalization import rewrite_args

    class _FakeSettings:
        mcp_strict_unknown_fields = False
        mcp_schema_key_normalization_enabled = True
        mcp_schema_key_normalization_meta = True

    monkeypatch.setattr(sn_mod, "settings", _FakeSettings())

    server = FastMCP("test")
    await _register_canonical_tool(server)

    args = {"unknownField": "x"}
    rewritten, events = await rewrite_args("adsv1_list_campaigns", args, server=server)

    assert rewritten == {"unknownField": "x"}
    assert events == [
        {
            "kind": "unknown_field_passed_through",
            "field": "unknownField",
            "reason": "no_schema_match",
        }
    ]


def test_ambiguous_match_leaves_unchanged():
    """Two schema fields normalize to the same token → leave caller's key alone.

    FastMCP/Pydantic can't express truly-colliding parameter names, so this
    test exercises the internal normalizer directly with a synthetic schema.
    """
    from amazon_ads_mcp.middleware.schema_normalization import (
        _normalize_args_with_schema,
    )

    args = {"UserId": "X"}  # token "userid" matches both `user_id` and `userId`
    rewritten, events = _normalize_args_with_schema(args, _ambiguous_schema_properties())

    assert rewritten == args
    # Round 12 follow-up: kind depends on MCP_STRICT_UNKNOWN_FIELDS
    # (default True → unknown_field_rejected). Accept either label so
    # the test is robust to the flag.
    assert any(
        e.get("kind") in ("unknown_field_passed_through", "unknown_field_rejected")
        for e in events
    )


@pytest.mark.asyncio
async def test_dropped_alias_when_canonical_present():
    from amazon_ads_mcp.middleware.schema_normalization import rewrite_args

    server = FastMCP("test")
    await _register_canonical_tool(server)

    args = {"marketplaceIds": ["A"], "MarketplaceIds": ["B"]}
    rewritten, events = await rewrite_args("adsv1_list_campaigns", args, server=server)

    assert "MarketplaceIds" not in rewritten
    assert rewritten["marketplaceIds"] == ["A"]  # canonical wins
    assert any(
        e.get("kind") == "dropped_alias"
        and e.get("from") == "MarketplaceIds"
        and e.get("canonical") == "marketplaceIds"
        for e in events
    )


@pytest.mark.asyncio
async def test_scalar_to_array_coercion_with_rename():
    from amazon_ads_mcp.middleware.schema_normalization import rewrite_args

    server = FastMCP("test")
    await _register_canonical_tool(server)

    args = {"MarketplaceIds": "ATVPDKIKX0DER"}
    rewritten, events = await rewrite_args("adsv1_list_campaigns", args, server=server)

    assert rewritten == {"marketplaceIds": ["ATVPDKIKX0DER"]}
    kinds = [e.get("kind") for e in events]
    assert "renamed" in kinds
    assert "coerced" in kinds


@pytest.mark.asyncio
async def test_canonical_input_no_changes_no_events():
    from amazon_ads_mcp.middleware.schema_normalization import rewrite_args

    server = FastMCP("test")
    await _register_canonical_tool(server)

    args = {"marketplaceIds": ["A"]}
    rewritten, events = await rewrite_args("adsv1_list_campaigns", args, server=server)

    assert rewritten == args
    assert events == []


# ---------------------------------------------------------------------------
# attempted_normalization semantics — emit even when no mutation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_attempted_normalization_emits_on_unknown_field():
    from amazon_ads_mcp.middleware.schema_normalization import rewrite_args

    server = FastMCP("test")
    await _register_canonical_tool(server)

    args = {"definitelyNotInSchema": 42}
    _, events = await rewrite_args("adsv1_list_campaigns", args, server=server)

    assert events, "attempted_normalization semantics: must emit even on no-match"
    # Round 12 follow-up: kind reflects strict-unknown setting.
    assert events[0]["kind"] in (
        "unknown_field_passed_through",
        "unknown_field_rejected",
    )


# ---------------------------------------------------------------------------
# Master switch
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_master_switch_disabled_short_circuits(monkeypatch):
    """When MCP_SCHEMA_KEY_NORMALIZATION_ENABLED=false, no rewrites or events.

    The middleware reads ``settings`` via ``from ..config.settings import
    settings`` so we patch the attribute through the middleware's own
    namespace. This is robust against conftest fixtures that rebind
    ``settings`` on unrelated modules between tests.
    """
    from amazon_ads_mcp.middleware.schema_normalization import rewrite_args

    monkeypatch.setattr(
        "amazon_ads_mcp.middleware.schema_normalization.settings.mcp_schema_key_normalization_enabled",
        False,
    )

    server = FastMCP("test")
    await _register_canonical_tool(server)

    args = {"MarketplaceIds": ["X"]}
    rewritten, events = await rewrite_args("adsv1_list_campaigns", args, server=server)
    assert rewritten == args
    assert events == []


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unknown_tool_name_passes_args_through():
    from amazon_ads_mcp.middleware.schema_normalization import rewrite_args

    server = FastMCP("test")
    args = {"any": "thing"}
    rewritten, events = await rewrite_args("nonexistent_tool", args, server=server)
    assert rewritten == args
    assert events == []


@pytest.mark.asyncio
async def test_none_args_treated_as_empty():
    from amazon_ads_mcp.middleware.schema_normalization import rewrite_args

    server = FastMCP("test")
    await _register_canonical_tool(server)
    rewritten, events = await rewrite_args("adsv1_list_campaigns", None, server=server)
    assert rewritten == {}
    assert events == []


@pytest.mark.asyncio
async def test_empty_dict_args_no_events():
    from amazon_ads_mcp.middleware.schema_normalization import rewrite_args

    server = FastMCP("test")
    await _register_canonical_tool(server)
    rewritten, events = await rewrite_args("adsv1_list_campaigns", {}, server=server)
    assert rewritten == {}
    assert events == []
