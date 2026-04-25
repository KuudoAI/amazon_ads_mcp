"""P1.5 — Filter-value enum guardrail for ``allv1_AdsApiv1CreateReport``.

Scope reminder:
- Catches obviously-invalid enum values (e.g. ``adProduct.value: "SPONSORED_PEANUTS"``)
  before the request leaves the server, so agents get a one-shot self-correction
  list instead of an opaque upstream 400.
- Does NOT fix the separate upstream issue where a valid ``SPONSORED_PRODUCTS``
  filter still returns Sponsored Brands rows. That's a spec-semantics mismatch
  tracked as an upstream ticket.

Walker handles the real v1 filter shape: ``reports[].query.filter`` is a
``oneOf({"and": {"filters": [...]}}, {"on": <ComparisonPredicate>})`` tree,
recursively nested. NOT a flat ``configuration.filters[]`` list.

Validator is sync; the middleware adapter around it is async.
"""

from __future__ import annotations

import pytest


# ---------- shared body builders ---------------------------------------------


def _body(filter_node):
    """Minimum-viable CreateReport body with an explicit filter tree."""
    return {
        "accessRequestedAccounts": [{"advertiserAccountId": "ENTITY123"}],
        "reports": [
            {
                "format": "GZIP_JSON",
                "periods": [
                    {"datePeriod": {"startDate": "2026-01-01", "endDate": "2026-01-07"}}
                ],
                "query": {"fields": ["campaign.id"], "filter": filter_node},
            }
        ],
    }


def _on(field, values):
    """Leaf ``{on: ComparisonPredicate}`` — all four ComparisonPredicate keys
    required by the spec."""
    return {
        "on": {
            "field": field,
            "comparisonOperator": "EQUALS",
            "not": False,
            "values": values,
        }
    }


# ---------- enum source lock -------------------------------------------------


def test_enum_source_is_live_spec_not_hardcoded_list():
    """The accepted-values set must be loaded from ``components.schemas.AdProduct.enum``
    in the bundled spec. Future spec refreshes auto-propagate; no hand-maintained
    allowlist to drift."""
    from amazon_ads_mcp.middleware.create_report_guardrail import (
        _load_ad_product_enum,
    )
    from amazon_ads_mcp.utils.openapi import load_bundled_spec

    assert set(_load_ad_product_enum()) == set(
        load_bundled_spec("AdsAPIv1All")["components"]["schemas"]["AdProduct"]["enum"]
    )


# ---------- sync validator tests --------------------------------------------


def test_valid_adproduct_value_passes_through():
    from amazon_ads_mcp.middleware import create_report_guardrail as guardrail

    body = _body({"and": {"filters": [_on("adProduct.value", ["SPONSORED_PRODUCTS"])]}})
    guardrail.validate_create_report_body(body)  # does not raise


def test_invalid_adproduct_value_rejected_with_spec_enum_list():
    from amazon_ads_mcp.middleware import create_report_guardrail as guardrail

    body = _body({"and": {"filters": [_on("adProduct.value", ["SPONSORED_PEANUTS"])]}})
    with pytest.raises(ValueError) as exc:
        guardrail.validate_create_report_body(body)
    msg = str(exc.value)
    assert "SPONSORED_PEANUTS" in msg
    # All spec-declared accepted values must appear so the agent can self-correct
    # in one round — no second round-trip to look them up.
    for accepted in (
        "AMAZON_DSP",
        "SPONSORED_BRANDS",
        "SPONSORED_DISPLAY",
        "SPONSORED_PRODUCTS",
        "SPONSORED_TELEVISION",
    ):
        assert accepted in msg
    assert "adProduct.value" in msg


def test_walker_recurses_through_nested_and_predicates():
    from amazon_ads_mcp.middleware import create_report_guardrail as guardrail

    # Nest the bad predicate two levels deep: the walker must find it.
    inner = {"and": {"filters": [_on("adProduct.value", ["BAD"])]}}
    body = _body({"and": {"filters": [inner]}})
    with pytest.raises(ValueError):
        guardrail.validate_create_report_body(body)


def test_bare_on_predicate_at_filter_root_is_also_walked():
    from amazon_ads_mcp.middleware import create_report_guardrail as guardrail

    # filter is oneOf(and|on) — an ``on`` at the root is a valid shape
    # and must be walked. (Not a list wrapped in ``and``.)
    body = _body(_on("adProduct.value", ["BAD"]))
    with pytest.raises(ValueError):
        guardrail.validate_create_report_body(body)


def test_unenforced_field_passes_through():
    from amazon_ads_mcp.middleware import create_report_guardrail as guardrail

    # Guardrail only knows about adProduct.value today. Other fields
    # (campaign.id, whatever) fail open — we don't pretend to validate
    # fields we don't have enums for.
    body = _body({"and": {"filters": [_on("campaign.id", ["whatever"])]}})
    guardrail.validate_create_report_body(body)  # does not raise


def test_structural_surprise_fails_open_not_closed():
    from amazon_ads_mcp.middleware import create_report_guardrail as guardrail

    # Unknown top-level predicate key — walker degrades to no-op, not crash.
    body = _body({"xor": {"filters": [_on("adProduct.value", ["SPONSORED_PRODUCTS"])]}})
    guardrail.validate_create_report_body(body)  # does not raise


def test_body_without_filter_is_fine():
    from amazon_ads_mcp.middleware import create_report_guardrail as guardrail

    # filter is OPTIONAL in CreateReportingQuery — unfiltered reports are valid.
    body = {
        "accessRequestedAccounts": [{"advertiserAccountId": "ENTITY123"}],
        "reports": [
            {
                "format": "GZIP_JSON",
                "periods": [
                    {"datePeriod": {"startDate": "2026-01-01", "endDate": "2026-01-07"}}
                ],
                "query": {"fields": ["campaign.id"]},
            }
        ],
    }
    guardrail.validate_create_report_body(body)


def test_multiple_bad_values_all_listed():
    from amazon_ads_mcp.middleware import create_report_guardrail as guardrail

    body = _body(
        {"and": {"filters": [_on("adProduct.value", ["BAD_ONE", "BAD_TWO"])]}}
    )
    with pytest.raises(ValueError) as exc:
        guardrail.validate_create_report_body(body)
    msg = str(exc.value)
    assert "BAD_ONE" in msg
    assert "BAD_TWO" in msg


def test_mixed_valid_and_invalid_values_still_rejects():
    from amazon_ads_mcp.middleware import create_report_guardrail as guardrail

    body = _body(
        {
            "and": {
                "filters": [
                    _on("adProduct.value", ["SPONSORED_PRODUCTS", "NOT_A_PRODUCT"])
                ]
            }
        }
    )
    with pytest.raises(ValueError) as exc:
        guardrail.validate_create_report_body(body)
    assert "NOT_A_PRODUCT" in str(exc.value)


# ---------- async middleware adapter wiring ---------------------------------


@pytest.mark.asyncio
async def test_middleware_rejects_bad_body_via_adapter(monkeypatch):
    """The async adapter routes on the ``allv1_AdsApiv1CreateReport`` operationId,
    calls the sync validator, and surfaces ``ValueError`` as ``ToolError`` so
    FastMCP renders it as a proper tool-level error to the client."""
    from unittest.mock import MagicMock

    from fastmcp.exceptions import ToolError

    from amazon_ads_mcp.middleware.create_report_guardrail import (
        CreateReportFilterGuardrailMiddleware,
    )

    mw = CreateReportFilterGuardrailMiddleware()
    ctx = MagicMock()
    ctx.message = MagicMock()
    ctx.message.name = "allv1_AdsApiv1CreateReport"
    ctx.message.arguments = {
        "body": _body({"and": {"filters": [_on("adProduct.value", ["BAD"])]}})
    }

    async def _never_called(_):  # should not run on rejection path
        raise AssertionError("call_next should not execute on rejection")

    with pytest.raises(ToolError) as exc:
        await mw.on_call_tool(ctx, _never_called)
    assert "BAD" in str(exc.value)


@pytest.mark.asyncio
async def test_middleware_passes_through_other_tools():
    """Adapter routes ONLY on the target op. Other tools must not be touched."""
    from unittest.mock import MagicMock

    from amazon_ads_mcp.middleware.create_report_guardrail import (
        CreateReportFilterGuardrailMiddleware,
    )

    mw = CreateReportFilterGuardrailMiddleware()
    ctx = MagicMock()
    ctx.message = MagicMock()
    ctx.message.name = "some_other_tool"
    ctx.message.arguments = {
        "body": _body({"and": {"filters": [_on("adProduct.value", ["DEFINITELY_BAD"])]}})
    }

    called = {"next": False}

    async def _next(_):
        called["next"] = True
        return "ok"

    result = await mw.on_call_tool(ctx, _next)
    assert called["next"] is True
    assert result == "ok"


@pytest.mark.asyncio
async def test_middleware_passes_through_valid_body():
    """On the target op, a valid body must flow through to the downstream handler."""
    from unittest.mock import MagicMock

    from amazon_ads_mcp.middleware.create_report_guardrail import (
        CreateReportFilterGuardrailMiddleware,
    )

    mw = CreateReportFilterGuardrailMiddleware()
    ctx = MagicMock()
    ctx.message = MagicMock()
    ctx.message.name = "allv1_AdsApiv1CreateReport"
    ctx.message.arguments = {
        "body": _body({"and": {"filters": [_on("adProduct.value", ["SPONSORED_PRODUCTS"])]}})
    }

    async def _next(_):
        return "ok"

    result = await mw.on_call_tool(ctx, _next)
    assert result == "ok"
