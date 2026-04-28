"""Round 13 B-5 — `report_fields(mode="lookup", field_id=...)` first-class.

Today, looking up a field by ID is impossible: ``mode="query"`` rejects
``field_id`` via ``SCHEMA_ADDITIONAL_PROPERTIES`` (Round 12 strict-
unknown default), and ``fields=["..."]`` is a substring/list filter
that returns false positives. Phase B-5 adds a dedicated lookup mode:

  - ``mode="lookup", field_id="metric.totalCost"`` → single record
  - ``mode="lookup", field_ids=[...]`` → ordered batch
  - misses return ``error: "not_found"`` records, not exceptions
  - cross-mode args (search/category/limit) → INVALID_MODE_ARGS

Tests pin the contract; implementation follows.
"""

from __future__ import annotations

import pytest

from amazon_ads_mcp.tools.report_fields_v1_handler import (
    ReportFieldsToolError,
    handle as report_fields_handle,
)


def _ok_lookup_kwargs(**overrides):
    """Minimum-viable lookup-mode kwargs."""
    base = {
        "mode": "lookup",
        "operation": "allv1_AdsApiv1CreateReport",
        "field_id": "metric.totalCost",
    }
    base.update(overrides)
    return base


# ---- Happy paths ---------------------------------------------------------


def test_lookup_returns_single_record_for_known_field_id() -> None:
    result = report_fields_handle(**_ok_lookup_kwargs(field_id="metric.totalCost"))
    payload = result.model_dump() if hasattr(result, "model_dump") else dict(result)
    fields = payload.get("fields") or []
    assert len(fields) == 1
    assert fields[0].get("field_id") == "metric.totalCost"


def test_lookup_field_ids_returns_records_in_request_order() -> None:
    result = report_fields_handle(
        mode="lookup",
        operation="allv1_AdsApiv1CreateReport",
        field_ids=["metric.totalCost", "campaign.id"],
    )
    payload = result.model_dump() if hasattr(result, "model_dump") else dict(result)
    fields = payload.get("fields") or []
    assert [f.get("field_id") for f in fields] == [
        "metric.totalCost",
        "campaign.id",
    ]


def test_lookup_unknown_field_id_returns_not_found_record() -> None:
    result = report_fields_handle(
        mode="lookup",
        operation="allv1_AdsApiv1CreateReport",
        field_id="metric.does_not_exist",
    )
    payload = result.model_dump() if hasattr(result, "model_dump") else dict(result)
    fields = payload.get("fields") or []
    assert len(fields) == 1
    rec = fields[0]
    assert rec.get("field_id") == "metric.does_not_exist"
    assert rec.get("error") == "not_found"


def test_lookup_mixed_known_and_unknown_preserves_order() -> None:
    result = report_fields_handle(
        mode="lookup",
        operation="allv1_AdsApiv1CreateReport",
        field_ids=["metric.totalCost", "metric.does_not_exist", "campaign.id"],
    )
    payload = result.model_dump() if hasattr(result, "model_dump") else dict(result)
    fields = payload.get("fields") or []
    ids = [f.get("field_id") for f in fields]
    assert ids == [
        "metric.totalCost",
        "metric.does_not_exist",
        "campaign.id",
    ]
    # Middle record is the not-found marker
    assert fields[1].get("error") == "not_found"
    # Found records do NOT carry the error key
    assert "error" not in fields[0] or fields[0].get("error") is None
    assert "error" not in fields[2] or fields[2].get("error") is None


# ---- INVALID_MODE_ARGS error surface ------------------------------------


def test_lookup_without_field_id_or_field_ids_rejected() -> None:
    with pytest.raises(ReportFieldsToolError) as exc:
        report_fields_handle(
            mode="lookup",
            operation="allv1_AdsApiv1CreateReport",
        )
    assert exc.value.code == "INVALID_MODE_ARGS"


def test_lookup_with_query_mode_arg_rejected() -> None:
    """Cross-mode args MUST be rejected so ``mode="lookup"`` stays a
    pure ID lookup, not a hybrid."""
    with pytest.raises(ReportFieldsToolError) as exc:
        report_fields_handle(
            mode="lookup",
            operation="allv1_AdsApiv1CreateReport",
            field_id="metric.totalCost",
            search="cost",
        )
    assert exc.value.code == "INVALID_MODE_ARGS"


def test_lookup_with_validate_mode_arg_rejected() -> None:
    with pytest.raises(ReportFieldsToolError) as exc:
        report_fields_handle(
            mode="lookup",
            operation="allv1_AdsApiv1CreateReport",
            field_id="metric.totalCost",
            validate_fields=["metric.clicks"],
        )
    assert exc.value.code == "INVALID_MODE_ARGS"


def test_lookup_field_id_and_field_ids_both_set_rejected() -> None:
    """Caller picks ONE — either single-field shortcut or batch."""
    with pytest.raises(ReportFieldsToolError) as exc:
        report_fields_handle(
            mode="lookup",
            operation="allv1_AdsApiv1CreateReport",
            field_id="metric.totalCost",
            field_ids=["campaign.id"],
        )
    assert exc.value.code == "INVALID_MODE_ARGS"


def test_lookup_drop_in_lookup_mode_allowed() -> None:
    """``drop=`` is a record-shaping arg; lookup also returns records,
    so drop should work the same way it does in query mode. Mirrors
    the wrapper's serialization (``exclude_none=True``)."""
    result = report_fields_handle(
        mode="lookup",
        operation="allv1_AdsApiv1CreateReport",
        field_id="metric.totalCost",
        drop=["compatible_dimensions", "incompatible_dimensions"],
    )
    # Mirror builtin_tools.py wrapper: exclude_none=True (so unset
    # optional keys aren't serialized as `null`).
    payload = result.model_dump(exclude_none=True)
    fields = payload.get("fields") or []
    assert len(fields) == 1
    rec = fields[0]
    assert "compatible_dimensions" not in rec
    assert "incompatible_dimensions" not in rec
    assert rec.get("field_id") == "metric.totalCost"
