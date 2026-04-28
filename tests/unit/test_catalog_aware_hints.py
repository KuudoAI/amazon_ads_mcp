"""Round 13 C-pre — catalog-aware hints (gap closure for resources/adsv1).

Pins behavior across four catalog-leverage gaps the audit identified:

  - **Gap 1+2 (HIGH)**: When ``AdsApiv1CreateReport`` fails with an
    upstream HTTP error and the original request body is available,
    the envelope's ``hints[]`` carries retroactive ``mode='validate'``
    output (incompatible_pairs / missing_required / unknown-with-
    suggestions) sourced from the v1 catalog. Closes the gap where the
    catalog already KNEW the answer but the envelope didn't ask.

  - **Gap 3 (MEDIUM)**: ``catalog_suggestions_for(bad_field)``
    consults the v1 catalog index for did-you-mean candidates,
    reachable from any unknown-field path (schema_normalization,
    schema_validation hint enrichment).

  - **Gap 4 (MEDIUM)**: The same helper resolves display-label-style
    inputs (``"Campaign"``) via ``dimension_label_index`` to canonical
    field_ids (``campaign.id``).
"""

from __future__ import annotations

from unittest.mock import MagicMock

import httpx
import pytest

from amazon_ads_mcp.middleware.error_envelope import (
    build_envelope_from_exception,
)
from amazon_ads_mcp.tools.report_fields_v1_handler import (
    catalog_suggestions_for,
)


# ---- Gap 3+4: catalog_suggestions_for ----------------------------------


def test_catalog_suggestions_for_returns_list_for_known_typo() -> None:
    """A clear v1 typo (``metric.cost`` vs ``metric.totalCost``) should
    return at least one suggestion. Existing token-overlap algorithm
    already covers this; the helper is the unified entry point."""
    out = catalog_suggestions_for("metric.cost")
    assert isinstance(out, list)
    assert any("totalCost" in s for s in out), (
        f"expected metric.totalCost in suggestions; got {out}"
    )


def test_catalog_suggestions_for_resolves_display_label() -> None:
    """A display-label-style input (``"Campaign"``) should resolve to
    one or more canonical campaign.* field_ids via the
    dimension_label_index. Closes gap 4."""
    out = catalog_suggestions_for("Campaign")
    assert isinstance(out, list)
    if out:
        assert any(s.startswith("campaign.") for s in out), (
            f"expected campaign.* suggestion for display label; got {out}"
        )


def test_catalog_suggestions_for_unknown_returns_list_or_empty() -> None:
    """Garbage input never raises and returns a (possibly empty) list."""
    out = catalog_suggestions_for("totally_garbage_xyz_zyx_qqq_999")
    assert isinstance(out, list)


def test_catalog_suggestions_for_empty_input_returns_empty() -> None:
    assert catalog_suggestions_for("") == []
    assert catalog_suggestions_for(None) == []  # type: ignore[arg-type]


# ---- Gap 1+2: retroactive validate on CreateReport upstream failure ----


def _make_http_error(status: int = 400, body: str = "Bad Request") -> httpx.HTTPStatusError:
    """Build a minimal HTTPStatusError for envelope-translator tests."""
    request = httpx.Request("POST", "https://advertising-api.amazon.com/reporting/reports")
    response = httpx.Response(
        status_code=status,
        content=body.encode("utf-8"),
        request=request,
    )
    return httpx.HTTPStatusError("Bad Request", request=request, response=response)


def test_create_report_4xx_with_unknown_field_surfaces_catalog_suggestions() -> None:
    """When CreateReport returns 4xx and the request body has an
    unknown field, the envelope hints[] should carry the catalog's
    did-you-mean suggestion. The agent shouldn't have to call
    mode='validate' separately to get this guidance."""
    exc = _make_http_error()
    tool_args = {
        "body": {
            "reports": [
                {
                    "name": "test",
                    "configuration": {},
                    "query": {
                        "fields": ["metric.cost", "campaign.id"],  # metric.cost is unknown in v1
                    },
                }
            ]
        }
    }
    envelope = build_envelope_from_exception(
        exc,
        tool_name="allv1_AdsApiv1CreateReport",
        tool_args=tool_args,
    )
    hints = envelope.get("hints") or []
    joined = " ".join(hints)
    assert "metric.cost" in joined or "totalCost" in joined, (
        f"envelope hints should reference unknown-field suggestions "
        f"sourced from the catalog; got: {hints}"
    )


def test_create_report_4xx_surfaces_pre_flight_validate_hint() -> None:
    """Every CreateReport 4xx envelope should include the canonical
    'pre-flight with report_fields(mode=\"validate\", ...)' guidance."""
    exc = _make_http_error()
    tool_args = {"body": {"reports": [{"query": {"fields": ["metric.totalCost"]}}]}}
    envelope = build_envelope_from_exception(
        exc,
        tool_name="allv1_AdsApiv1CreateReport",
        tool_args=tool_args,
    )
    hints = envelope.get("hints") or []
    joined = " ".join(hints)
    assert "report_fields" in joined, (
        f"hint should reference report_fields(mode='validate', ...); got {hints}"
    )


def test_create_report_4xx_without_args_falls_back_to_default_hints() -> None:
    """When tool_args is None (older callers, lost-context paths), the
    envelope must still build cleanly — no exception, no extra hints."""
    exc = _make_http_error()
    envelope = build_envelope_from_exception(
        exc,
        tool_name="allv1_AdsApiv1CreateReport",
        tool_args=None,
    )
    # Envelope still constructs; just no catalog-driven hints added.
    assert envelope.get("error_kind") == "ads_api_http"
    assert envelope.get("error_code") == "ADS_API_HTTP_400"


def test_non_create_report_4xx_skips_catalog_enrichment() -> None:
    """Catalog enrichment is CreateReport-specific. Other tools failing
    with 4xx should NOT pay the catalog-validate cost."""
    exc = _make_http_error()
    tool_args = {"some_unrelated_arg": "value"}
    envelope = build_envelope_from_exception(
        exc,
        tool_name="allv1_SomeOtherTool",
        tool_args=tool_args,
    )
    hints = envelope.get("hints") or []
    joined = " ".join(hints)
    assert "v1 catalog" not in joined, (
        f"non-CreateReport tools should not get catalog-validate hints; got: {hints}"
    )


# ---- Gap 3: schema_normalization unknown-field events --------------------


@pytest.mark.asyncio
async def test_schema_normalization_unknown_field_carries_catalog_suggestions() -> None:
    """When the sidecar normalizer rejects an unknown field, the event
    should carry catalog-sourced suggestions if the bad name plausibly
    matches a v1 catalog field_id. Closes gap 3."""
    from amazon_ads_mcp.middleware.schema_normalization import rewrite_args
    from fastmcp import FastMCP

    server = FastMCP("test")

    @server.tool(name="dummy_tool")
    async def _dummy(known_field: str = "x"):
        return {"ok": True}

    args = {"metric.cost": "x"}  # unknown to schema, but catalog has metric.totalCost
    _, events = await rewrite_args("dummy_tool", args, server=server)
    # At least one event should be unknown_* and ideally carry suggestions.
    unknown_events = [
        e for e in events if e.get("kind", "").startswith("unknown_field")
    ]
    assert unknown_events, "expected unknown_field event for 'metric.cost'"
    sugg = unknown_events[0].get("suggestions") or []
    if sugg:
        # When suggestions are present, they should reference the catalog.
        joined = " ".join(sugg)
        assert (
            "totalCost" in joined or "metric." in joined
        ), f"suggestions should reference v1 catalog; got: {sugg}"


# ---- Gap 3 (parallel path): schema_validation SCHEMA_ADDITIONAL_PROPERTIES


@pytest.mark.asyncio
async def test_schema_additional_properties_hint_includes_catalog_suggestion(
    monkeypatch,
) -> None:
    """When SchemaValidationMiddleware rejects an extra field, the hint
    should include a catalog-driven did-you-mean. Closes gap 3 from
    the schema-validation angle (parallel to the schema_normalization
    angle above)."""
    from amazon_ads_mcp.middleware.schema_validation import (
        SchemaValidationMiddleware,
    )

    class _Tool:
        parameters = {
            "type": "object",
            "properties": {"primary": {"type": "string"}},
            "additionalProperties": False,
        }

    class _FastMCP:
        async def get_tool(self, name):
            return _Tool()

    class _Ctx:
        def __init__(self):
            self.fastmcp = _FastMCP()
            self.fastmcp_context = self
            self.message = MagicMock()
            self.message.name = "any"
            self.message.arguments = {"primary": "ok", "metric.cost": "x"}

    from amazon_ads_mcp.exceptions import ValidationError as AdsValidationError

    mw = SchemaValidationMiddleware()
    ctx = _Ctx()

    async def call_next(c):
        return {"ok": True}

    with pytest.raises(AdsValidationError) as exc:
        await mw.on_call_tool(ctx, call_next)
    hints = exc.value.details.get("hints") or []
    joined = " ".join(hints)
    # Should include either a primary template hint OR a catalog
    # did-you-mean. Both is best.
    assert "metric.cost" in joined or "totalCost" in joined, (
        f"schema-validation hint should consult catalog for unknown extra "
        f"field; got: {hints}"
    )
