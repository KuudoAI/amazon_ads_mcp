"""Unit tests for strict unknown-field rejection (Commit 2 of fix/mcp-surface-quality).

Verifies the ``check_strict_unknown_fields`` helper in schema_normalization
which sidecar middleware invokes AFTER all rewrites. Critical contract:

- Default off: pass-through preserved (back-compat for fields ahead of spec)
- Strict on: truly unknown fields raise ValidationError with did_you_mean
- Strict on: sidecar-rewritten canonical keys (e.g. ``reportIds`` after a
  ``reportId`` → ``reportIds`` alias rewrite) are NOT rejected

The middleware-ordering-aware behavior is tested via direct invocation of
``check_strict_unknown_fields`` against the post-rewrite args. Smoke test
in tests/integration/test_strict_unknown_fields_smoke.py exercises the
full middleware chain through a real MCP server.
"""

from __future__ import annotations

from typing import List, Optional

import pytest
from fastmcp import FastMCP
from pydantic import Field

from amazon_ads_mcp.middleware.schema_normalization import (
    check_strict_unknown_fields,
)
from amazon_ads_mcp.utils.errors import ErrorCategory, ValidationError


@pytest.fixture
def server_with_known_tool():
    server = FastMCP(name="test-strict")

    @server.tool(name="known_tool")
    async def known_tool(
        maxResults: Optional[int] = None,
        marketplaceIds: List[str] = Field(default_factory=list),
        campaignId: Optional[str] = None,
    ) -> dict:
        return {"maxResults": maxResults, "marketplaceIds": marketplaceIds}

    return server


# ---------------------------------------------------------------------------
# Default off: pass-through preserved
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_strict_off_passes_through_unknown_fields(
    monkeypatch, server_with_known_tool
):
    """Default behavior: unknown fields are NOT rejected. Back-compat with
    callers using fields that are valid at Amazon but not yet in our spec."""
    monkeypatch.setenv("MCP_STRICT_UNKNOWN_FIELDS", "false")
    from amazon_ads_mcp.config.settings import Settings
    from amazon_ads_mcp.middleware import schema_normalization as sn_module

    monkeypatch.setattr(sn_module, "settings", Settings())

    # Should NOT raise — strict mode off
    await check_strict_unknown_fields(
        "known_tool",
        {"maxResult": 10, "totalNonsenseParam": "lol"},
        server=server_with_known_tool,
    )


# ---------------------------------------------------------------------------
# Strict on: truly unknown fields raise with did_you_mean
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_strict_on_typo_raises_with_did_you_mean(
    monkeypatch, server_with_known_tool
):
    """Strict mode + typo'd field → ValidationError with did_you_mean
    suggesting the canonical name."""
    monkeypatch.setenv("MCP_STRICT_UNKNOWN_FIELDS", "true")
    from amazon_ads_mcp.config.settings import Settings
    from amazon_ads_mcp.middleware import schema_normalization as sn_module

    # The module imports `settings` directly at module load time, so we
    # have to patch the bound name in the module, not the source.
    monkeypatch.setattr(sn_module, "settings", Settings())

    with pytest.raises(ValidationError) as excinfo:
        await check_strict_unknown_fields(
            "known_tool",
            {"maxResult": 10},
            server=server_with_known_tool,
        )

    err = excinfo.value
    assert err.category == ErrorCategory.VALIDATION
    assert "maxResult" in str(err)
    assert err.details.get("error_code") == "UNKNOWN_FIELD"
    hints = err.details.get("hints", [])
    assert hints, f"expected did_you_mean hints, got {err.details}"
    suggestions = hints[0].get("suggestions", [])
    assert "maxResults" in suggestions, (
        f"expected maxResults in did_you_mean, got {suggestions}"
    )


@pytest.mark.asyncio
async def test_strict_on_unknown_no_close_match_raises_without_suggestions(
    monkeypatch, server_with_known_tool
):
    """An unknown field with no close match still raises, but with no
    suggestions (cutoff=0.5 in get_close_matches)."""
    monkeypatch.setenv("MCP_STRICT_UNKNOWN_FIELDS", "true")
    from amazon_ads_mcp.config.settings import Settings
    from amazon_ads_mcp.middleware import schema_normalization as sn_module

    # The module imports `settings` directly at module load time, so we
    # have to patch the bound name in the module, not the source.
    monkeypatch.setattr(sn_module, "settings", Settings())

    with pytest.raises(ValidationError) as excinfo:
        await check_strict_unknown_fields(
            "known_tool",
            {"totalNonsenseParam": "lol"},
            server=server_with_known_tool,
        )

    err = excinfo.value
    assert "totalNonsenseParam" in str(err)
    hints = err.details.get("hints", [])
    if hints:
        # If there's a hint, it should NOT have suggestions for this nonsense
        assert not hints[0].get("suggestions"), (
            f"unexpected suggestions for totally-wrong field: {hints}"
        )


@pytest.mark.asyncio
async def test_strict_on_known_field_passes_through(
    monkeypatch, server_with_known_tool
):
    """Regression: known fields don't trigger the strict check."""
    monkeypatch.setenv("MCP_STRICT_UNKNOWN_FIELDS", "true")
    from amazon_ads_mcp.config.settings import Settings
    from amazon_ads_mcp.middleware import schema_normalization as sn_module

    # The module imports `settings` directly at module load time, so we
    # have to patch the bound name in the module, not the source.
    monkeypatch.setattr(sn_module, "settings", Settings())

    await check_strict_unknown_fields(
        "known_tool",
        {"maxResults": 10, "marketplaceIds": ["US"]},
        server=server_with_known_tool,
    )


# ---------------------------------------------------------------------------
# Critical: sidecar-aliased fields survive strict mode (ordering test)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_strict_on_canonical_after_sidecar_rewrite_survives(
    monkeypatch, server_with_known_tool
):
    """Critical contract: the strict check sees args AFTER sidecar's alias
    rewrites. So a caller who sent ``campaignIds: [...]`` (ambiguous to
    schema_normalization → passed through) but had it rewritten by a sidecar
    overlay to canonical ``campaignId`` would NOT be rejected here.

    This test simulates the post-sidecar state: pass canonical args, expect
    no rejection. The sidecar middleware's role is to make this canonical;
    our role is to NOT reject what the sidecar already legalized."""
    monkeypatch.setenv("MCP_STRICT_UNKNOWN_FIELDS", "true")
    from amazon_ads_mcp.config.settings import Settings
    from amazon_ads_mcp.middleware import schema_normalization as sn_module

    # The module imports `settings` directly at module load time, so we
    # have to patch the bound name in the module, not the source.
    monkeypatch.setattr(sn_module, "settings", Settings())

    # Simulating: caller sent ``reportId`` (alias), sidecar rewrote to
    # canonical ``campaignId``. The strict check sees the canonical form.
    await check_strict_unknown_fields(
        "known_tool",
        {"campaignId": "ABC123"},
        server=server_with_known_tool,
    )


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_strict_on_empty_args_no_op(monkeypatch, server_with_known_tool):
    """Empty args list is a no-op in strict mode."""
    monkeypatch.setenv("MCP_STRICT_UNKNOWN_FIELDS", "true")
    from amazon_ads_mcp.config.settings import Settings
    from amazon_ads_mcp.middleware import schema_normalization as sn_module

    # The module imports `settings` directly at module load time, so we
    # have to patch the bound name in the module, not the source.
    monkeypatch.setattr(sn_module, "settings", Settings())

    await check_strict_unknown_fields(
        "known_tool", {}, server=server_with_known_tool
    )
    await check_strict_unknown_fields(
        "known_tool", None, server=server_with_known_tool
    )


@pytest.mark.asyncio
async def test_strict_on_unresolvable_schema_no_op(monkeypatch):
    """When the tool's schema can't be resolved (e.g. tool not registered),
    strict mode is a no-op — we can't validate against nothing."""
    monkeypatch.setenv("MCP_STRICT_UNKNOWN_FIELDS", "true")
    from amazon_ads_mcp.config.settings import Settings
    from amazon_ads_mcp.middleware import schema_normalization as sn_module

    # The module imports `settings` directly at module load time, so we
    # have to patch the bound name in the module, not the source.
    monkeypatch.setattr(sn_module, "settings", Settings())

    server = FastMCP(name="empty")
    # No tool named "missing_tool" — properties lookup returns {}
    await check_strict_unknown_fields(
        "missing_tool", {"anything": 1}, server=server
    )


@pytest.mark.asyncio
async def test_strict_on_multiple_unknowns_raises_once_with_all(
    monkeypatch, server_with_known_tool
):
    """Multiple unknown fields → single ValidationError listing all of them
    in details.unknown_fields."""
    monkeypatch.setenv("MCP_STRICT_UNKNOWN_FIELDS", "true")
    from amazon_ads_mcp.config.settings import Settings
    from amazon_ads_mcp.middleware import schema_normalization as sn_module

    # The module imports `settings` directly at module load time, so we
    # have to patch the bound name in the module, not the source.
    monkeypatch.setattr(sn_module, "settings", Settings())

    with pytest.raises(ValidationError) as excinfo:
        await check_strict_unknown_fields(
            "known_tool",
            {"maxResult": 10, "totalNonsenseParam": "lol"},
            server=server_with_known_tool,
        )

    err = excinfo.value
    unknowns = err.details.get("unknown_fields", [])
    assert sorted(unknowns) == ["maxResult", "totalNonsenseParam"]
