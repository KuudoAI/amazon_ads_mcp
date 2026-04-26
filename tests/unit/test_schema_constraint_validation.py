"""Unit tests for dispatcher-level jsonschema constraint validation (R1).

The validator runs in ``SidecarTransformMiddleware.on_call_tool`` AFTER
schema-key normalization and sidecar alias rewrites, BEFORE the existing
strict-unknown-fields check. It uses ``jsonschema.Draft202012Validator`` to
catch type / enum / required / numeric-bounds / array-bounds violations
locally (no Amazon round-trip), and translates failures into
:class:`ValidationError` so the envelope translator emits
``error_kind: mcp_input_validation`` / ``error_code: INPUT_VALIDATION_FAILED``.

Covers:
- 8 client-reported R1 cases (missing-required, type, enum, bounds, array bounds)
- Default-on contract (no env override required)
- Opt-out path (MCP_SCHEMA_CONSTRAINT_VALIDATION_ENABLED=false)
- Schema lookup failure → fail open with telemetry
- No-schema graceful degradation
- Sidecar alias survival (extra_known_fields exemption)
- Multi-error response (all errors surfaced in details[])
- Path format lock (a.b[0] not a.b.0)
"""

from __future__ import annotations

from typing import List

import pytest
from fastmcp import FastMCP
from pydantic import BaseModel, Field

from amazon_ads_mcp.middleware.schema_normalization import (
    check_schema_constraints,
)
from amazon_ads_mcp.utils.errors import ErrorCategory, ValidationError


class _AdProductFilter(BaseModel):
    """Nested model for testing object-typed schema validation."""

    include: List[str] = Field(default_factory=list, max_length=1, min_length=1)


@pytest.fixture
def server_with_constrained_tool():
    """A FastMCP server with a tool whose input schema declares meaningful
    constraints: required fields, enum, numeric bounds, array bounds, types.
    """
    server = FastMCP(name="test-constraints")

    @server.tool(name="constrained_tool")
    async def constrained_tool(
        adProductFilter: _AdProductFilter,
        maxResults: int = Field(100, ge=1, le=5000),
    ) -> dict:
        return {"received": True}

    return server


@pytest.fixture(autouse=True)
def _enable_constraint_validation(monkeypatch):
    """Most tests below want the validator on. Per-test opt-out by
    setting MCP_SCHEMA_CONSTRAINT_VALIDATION_ENABLED=false."""
    from amazon_ads_mcp.config.settings import Settings
    from amazon_ads_mcp.middleware import schema_normalization as sn_module

    monkeypatch.setattr(sn_module, "settings", Settings())


# ---------------------------------------------------------------------------
# Default-on contract (no env override needed)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_default_on_without_env(monkeypatch, server_with_constrained_tool):
    """With NO env override, the validator runs and rejects bad input.
    Locks the safe-by-default contract per repo policy."""
    monkeypatch.delenv(
        "MCP_SCHEMA_CONSTRAINT_VALIDATION_ENABLED", raising=False
    )
    from amazon_ads_mcp.config.settings import Settings
    from amazon_ads_mcp.middleware import schema_normalization as sn_module

    fresh = Settings()
    assert fresh.mcp_schema_constraint_validation_enabled is True
    monkeypatch.setattr(sn_module, "settings", fresh)

    with pytest.raises(ValidationError):
        await check_schema_constraints(
            "constrained_tool",
            {},
            server=server_with_constrained_tool,
        )


@pytest.mark.asyncio
async def test_opt_out_disables_validation(
    monkeypatch, server_with_constrained_tool
):
    """MCP_SCHEMA_CONSTRAINT_VALIDATION_ENABLED=false → no validation,
    bad input passes through (current pre-R1 behavior)."""
    monkeypatch.setenv("MCP_SCHEMA_CONSTRAINT_VALIDATION_ENABLED", "false")
    from amazon_ads_mcp.config.settings import Settings
    from amazon_ads_mcp.middleware import schema_normalization as sn_module

    monkeypatch.setattr(sn_module, "settings", Settings())

    await check_schema_constraints(
        "constrained_tool",
        {},
        server=server_with_constrained_tool,
    )


# ---------------------------------------------------------------------------
# 8 client-reported R1 cases
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_missing_required_field(server_with_constrained_tool):
    """Case 1: empty args → missing required `adProductFilter`."""
    with pytest.raises(ValidationError) as excinfo:
        await check_schema_constraints(
            "constrained_tool",
            {},
            server=server_with_constrained_tool,
        )
    err = excinfo.value
    assert err.category == ErrorCategory.VALIDATION
    assert err.details.get("error_code") == "INPUT_VALIDATION_FAILED"
    msg = str(err).lower()
    assert "required" in msg or "adproductfilter" in msg


@pytest.mark.asyncio
async def test_type_mismatch_object_expected_string_given(
    server_with_constrained_tool,
):
    """Case 2: `adProductFilter` declared as object, string passed."""
    with pytest.raises(ValidationError) as excinfo:
        await check_schema_constraints(
            "constrained_tool",
            {"adProductFilter": "not_an_object"},
            server=server_with_constrained_tool,
        )
    err = excinfo.value
    assert err.category == ErrorCategory.VALIDATION
    msg = str(err).lower()
    assert "object" in msg or "type" in msg or "string" in msg


@pytest.mark.asyncio
async def test_max_above_schema_ceiling(server_with_constrained_tool):
    """Case 3: maxResults=5001 (schema max=5000) raises locally."""
    with pytest.raises(ValidationError):
        await check_schema_constraints(
            "constrained_tool",
            {
                "adProductFilter": {"include": ["SP"]},
                "maxResults": 5001,
            },
            server=server_with_constrained_tool,
        )


@pytest.mark.asyncio
async def test_max_below_schema_floor_zero(server_with_constrained_tool):
    """Case 4: maxResults=0 (schema min=1) raises locally."""
    with pytest.raises(ValidationError):
        await check_schema_constraints(
            "constrained_tool",
            {
                "adProductFilter": {"include": ["SP"]},
                "maxResults": 0,
            },
            server=server_with_constrained_tool,
        )


@pytest.mark.asyncio
async def test_max_below_schema_floor_negative(server_with_constrained_tool):
    """Case 5: maxResults=-1 (schema min=1) raises locally."""
    with pytest.raises(ValidationError):
        await check_schema_constraints(
            "constrained_tool",
            {
                "adProductFilter": {"include": ["SP"]},
                "maxResults": -1,
            },
            server=server_with_constrained_tool,
        )


@pytest.mark.asyncio
async def test_empty_array_violates_min_items(server_with_constrained_tool):
    """Case 7: adProductFilter.include=[] violates min_length=1."""
    with pytest.raises(ValidationError) as excinfo:
        await check_schema_constraints(
            "constrained_tool",
            {
                "adProductFilter": {"include": []},
            },
            server=server_with_constrained_tool,
        )
    err = excinfo.value
    msg = str(err).lower()
    assert "short" in msg or "min" in msg or "length" in msg or "include" in msg


@pytest.mark.asyncio
async def test_too_many_array_items_violates_max_items(
    server_with_constrained_tool,
):
    """Case 8: adProductFilter.include with 2 items violates max_length=1."""
    with pytest.raises(ValidationError) as excinfo:
        await check_schema_constraints(
            "constrained_tool",
            {
                "adProductFilter": {
                    "include": ["SPONSORED_PRODUCTS", "SPONSORED_BRANDS"]
                },
            },
            server=server_with_constrained_tool,
        )
    err = excinfo.value
    msg = str(err).lower()
    assert "long" in msg or "max" in msg or "include" in msg


@pytest.mark.asyncio
async def test_bad_enum_value():
    """Case 6: enum violation — caught locally, full enum list survives.

    The client specifically called out that Amazon truncates the helpful
    enum list at "[SPONSORED_PRODUCT...". A local validator should NOT
    truncate; the full list must be in the error message.
    """
    server = FastMCP(name="enum-test")

    @server.tool(name="enum_tool")
    async def enum_tool(adProduct: str) -> dict:
        return {"received": True}

    # Manually patch the tool's parameter schema to declare an enum.
    tool = await server.get_tool("enum_tool")
    tool.parameters["properties"]["adProduct"] = {
        "type": "string",
        "enum": [
            "AMAZON_DSP",
            "SPONSORED_BRANDS",
            "SPONSORED_DISPLAY",
            "SPONSORED_PRODUCTS",
            "SPONSORED_TELEVISION",
        ],
    }

    with pytest.raises(ValidationError) as excinfo:
        await check_schema_constraints(
            "enum_tool",
            {"adProduct": "NOT_A_REAL_AD_PRODUCT"},
            server=server,
        )
    err = excinfo.value
    msg = str(err)
    assert "SPONSORED_PRODUCTS" in msg, (
        f"expected full enum list in error, got truncated: {msg!r}"
    )


# ---------------------------------------------------------------------------
# Valid input — must NOT raise (regression baseline)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_valid_input_passes_through(server_with_constrained_tool):
    """Well-formed input must NOT raise — validator is additive, not
    blocking legitimate calls."""
    await check_schema_constraints(
        "constrained_tool",
        {
            "adProductFilter": {"include": ["SPONSORED_PRODUCTS"]},
            "maxResults": 100,
        },
        server=server_with_constrained_tool,
    )


# ---------------------------------------------------------------------------
# Schema lookup graceful degradation (fail-open with telemetry)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_no_schema_no_op():
    """Tool with no resolvable schema → no-op (fail open)."""
    server = FastMCP(name="empty")
    await check_schema_constraints(
        "missing_tool",
        {"anything": 1},
        server=server,
    )


@pytest.mark.asyncio
async def test_schema_lookup_exception_fails_open(monkeypatch, caplog):
    """If the schema lookup raises (e.g. $ref resolution failure), the
    validator must fail OPEN and emit telemetry — never break tool execution.

    Locks feedback_fail_open_telemetry.md contract.
    """
    from amazon_ads_mcp.middleware import schema_normalization as sn_module

    async def _raises(*args, **kwargs):
        raise RuntimeError("simulated $ref resolution failure")

    monkeypatch.setattr(sn_module, "_get_tool_input_schema", _raises)

    import logging

    with caplog.at_level(logging.WARNING):
        await check_schema_constraints(
            "any_tool",
            {"some": "args"},
            server=None,
        )

    assert any(
        "schema_lookup_failed" in record.message
        or "schema lookup" in record.message.lower()
        for record in caplog.records
    ), f"expected telemetry log, got {[r.message for r in caplog.records]}"


# ---------------------------------------------------------------------------
# Sidecar alias survival (extra_known_fields exemption)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_extra_known_fields_exempts_sidecar_aliases(
    server_with_constrained_tool,
):
    """Sidecar's arg_aliases is additive — the source key (e.g. `reportId`)
    stays in args alongside the rewritten canonical (`reportIds`). The
    validator must exempt those source keys via extra_known_fields,
    matching the strict-unknown-fields exemption pattern."""
    await check_schema_constraints(
        "constrained_tool",
        {
            "adProductFilter": {"include": ["SP"]},
            "maxResults": 100,
            "extraField": "alias-source-value",
        },
        server=server_with_constrained_tool,
        extra_known_fields={"extraField"},
    )


@pytest.mark.asyncio
async def test_unknown_field_without_exemption_raises(
    server_with_constrained_tool,
):
    """Confirm the exemption test above isn't a no-op: without
    extra_known_fields, the same call must raise (additionalProperties
    is enforced by the validator, regardless of schema declaration)."""
    with pytest.raises(ValidationError):
        await check_schema_constraints(
            "constrained_tool",
            {
                "adProductFilter": {"include": ["SP"]},
                "maxResults": 100,
                "extraField": "rogue-value",
            },
            server=server_with_constrained_tool,
        )


# ---------------------------------------------------------------------------
# Multi-error response
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_multi_error_surfaces_all_violations(server_with_constrained_tool):
    """When input has multiple violations, surface them all in
    details["violations"] so the caller can fix everything in one
    round-trip, not N."""
    with pytest.raises(ValidationError) as excinfo:
        await check_schema_constraints(
            "constrained_tool",
            {
                "adProductFilter": "not_an_object",
                "maxResults": 9999,
            },
            server=server_with_constrained_tool,
        )
    err = excinfo.value
    violations = err.details.get("violations", [])
    assert len(violations) >= 2, (
        f"expected multiple violations in details, got {violations}"
    )


# ---------------------------------------------------------------------------
# Path format lock — a.b[0] (bracketed indices), not a.b.0
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_path_format_uses_bracket_for_array_indices(
    server_with_constrained_tool,
):
    """Path format contract: nested keys joined with dots, array indices
    in brackets. Disambiguates index-vs-key."""
    with pytest.raises(ValidationError) as excinfo:
        await check_schema_constraints(
            "constrained_tool",
            {"adProductFilter": {"include": [123]}},
            server=server_with_constrained_tool,
        )
    err = excinfo.value
    violations = err.details.get("violations", [])
    assert violations
    paths = [v.get("path", "") for v in violations]
    assert any("[0]" in p for p in paths), (
        f"expected bracketed index in path, got paths={paths}"
    )
