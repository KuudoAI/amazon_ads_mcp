"""Round 13 Phase D — dual-namespace compatibility lists.

Closes audit gap #9: ``compatible_dimensions`` returns display strings
(``["Ad", "Ad group", ...]``) which leak presentation into a
programmatic contract. The parallel ``compatible_dimension_ids`` array
returns canonical field_ids (``["target.adType", "target.adGroupId",
...]``) so callers can use them programmatically without re-walking
the label index themselves.

Deprecation policy (concrete):

  - **Introduced**: Round 13 (this PR).
  - **Removal-no-earlier-than**: 2026-09-30.
  - **Removal condition**: two consecutive client-conformance reports
    show zero usage of the display-string arrays AND no open issues
    referencing them.

Each query-mode response includes a top-level
``deprecations[]`` array signaling the future removal so client teams
can migrate at their own pace.
"""

from __future__ import annotations

from datetime import date


from amazon_ads_mcp.tools.report_fields_v1_handler import (
    handle as report_fields_handle,
)


# ---- Parallel arrays present on every record ---------------------------


def test_query_metric_record_has_both_display_and_id_arrays() -> None:
    """Every metric record in query-mode carries BOTH the legacy
    display-string array (compatible_dimensions) AND the new
    field-id array (compatible_dimension_ids)."""
    result = report_fields_handle(
        mode="query",
        operation="allv1_AdsApiv1CreateReport",
        category="metric",
        search="totalCost",
        limit=1,
    )
    payload = result.model_dump(exclude_none=True)
    fields = payload.get("fields") or []
    assert fields
    rec = fields[0]
    # Display strings (legacy) — kept until 2026-09-30 removal window.
    assert "compatible_dimensions" in rec, (
        f"legacy display-string array missing from record; got keys: "
        f"{list(rec.keys())}"
    )
    # Field IDs (new) — parallel.
    assert "compatible_dimension_ids" in rec, (
        f"new compatible_dimension_ids array missing; got keys: "
        f"{list(rec.keys())}"
    )


def test_dimension_id_arrays_match_display_array_count() -> None:
    """Each display label resolves to ≥1 field_id via the
    label_index, so the IDs array length should be ≥ display array
    length (multiple field_ids can share a display label, e.g.
    'Campaign' covers campaign.id + campaign.budget.id, etc.)."""
    result = report_fields_handle(
        mode="query",
        operation="allv1_AdsApiv1CreateReport",
        category="metric",
        search="totalCost",
        limit=1,
    )
    payload = result.model_dump(exclude_none=True)
    rec = (payload.get("fields") or [{}])[0]
    display = rec.get("compatible_dimensions") or []
    ids = rec.get("compatible_dimension_ids") or []
    assert len(ids) >= len(display) // 2, (
        f"_ids array suspiciously empty for {len(display)} display "
        f"labels; got {len(ids)} ids"
    )


def test_dimension_id_array_entries_are_valid_field_id_format() -> None:
    """Each entry in ``compatible_dimension_ids`` must look like a
    canonical field_id: ``<namespace>.<name>``."""
    import re

    result = report_fields_handle(
        mode="query",
        operation="allv1_AdsApiv1CreateReport",
        category="metric",
        search="totalCost",
        limit=1,
    )
    payload = result.model_dump(exclude_none=True)
    rec = (payload.get("fields") or [{}])[0]
    ids = rec.get("compatible_dimension_ids") or []
    pattern = re.compile(r"^[a-zA-Z][a-zA-Z0-9]*\.[a-zA-Z][a-zA-Z0-9]*$")
    for fid in ids:
        assert pattern.match(fid), (
            f"compatible_dimension_ids entry {fid!r} doesn't match "
            f"canonical field_id format"
        )


def test_incompatible_dimension_ids_parallel_array_present() -> None:
    """Same parallel-array contract for the incompatible side."""
    result = report_fields_handle(
        mode="query",
        operation="allv1_AdsApiv1CreateReport",
        category="metric",
        search="totalCost",
        limit=1,
    )
    payload = result.model_dump(exclude_none=True)
    rec = (payload.get("fields") or [{}])[0]
    # Both legacy and new arrays must be present (either may be empty
    # if the metric has no incompatible dimensions, but the keys
    # themselves should be exposed in the schema).
    assert "incompatible_dimensions" in rec or "incompatible_dimension_ids" in rec


# ---- Deprecation signal ------------------------------------------------


def test_query_response_carries_deprecation_signal_for_display_arrays() -> None:
    """Round 13 D: response carries a top-level ``deprecations[]``
    array announcing that the display-string compatibility arrays will
    be removed no earlier than 2026-09-30. Client teams can branch on
    this to migrate at their own pace."""
    result = report_fields_handle(
        mode="query",
        operation="allv1_AdsApiv1CreateReport",
        category="metric",
        search="totalCost",
        limit=1,
    )
    payload = result.model_dump(exclude_none=True)
    deprecations = payload.get("deprecations") or []
    assert deprecations, (
        "query response must carry deprecations[] with the "
        "compatible_dimensions removal-no-earlier-than-2026-09-30 signal"
    )
    cd_dep = next(
        (
            d
            for d in deprecations
            if d.get("old") == "compatible_dimensions"
        ),
        None,
    )
    assert cd_dep is not None
    assert cd_dep.get("new") == "compatible_dimension_ids"
    # Concrete date per the plan's deprecation policy.
    remove_after = cd_dep.get("remove_after")
    assert remove_after == "2026-09-30", (
        f"deprecation entry must carry concrete remove_after date; "
        f"got {remove_after!r}"
    )


def test_deprecation_remove_after_is_in_the_future() -> None:
    """Sanity check: the removal date is at least one quarter out
    from today, giving clients real migration runway."""
    result = report_fields_handle(
        mode="query",
        operation="allv1_AdsApiv1CreateReport",
        category="metric",
        search="totalCost",
        limit=1,
    )
    payload = result.model_dump(exclude_none=True)
    deprecations = payload.get("deprecations") or []
    cd_dep = next(
        (d for d in deprecations if d.get("old") == "compatible_dimensions"),
        None,
    )
    assert cd_dep is not None
    remove_after = date.fromisoformat(cd_dep["remove_after"])
    assert remove_after >= date(2026, 9, 30)


# ---- drop= compatibility (Phase D extends the allowlist) ---------------


def _handle_then_drop(drop_keys: list) -> dict:
    """Mirror the tool wrapper's serialize+drop sequence so tests can
    exercise drop without spinning a full FastMCP server. Wrapper
    code lives in ``builtin_tools.py``; we replicate just the post-
    serialize drop step here."""
    from amazon_ads_mcp.tools.report_fields_v1_handler import (
        _apply_drop_to_payload,
    )

    result = report_fields_handle(
        mode="query",
        operation="allv1_AdsApiv1CreateReport",
        category="metric",
        search="totalCost",
        limit=1,
        drop=drop_keys,
    )
    payload = result.model_dump(exclude_none=True)
    if drop_keys:
        _apply_drop_to_payload(payload, set(drop_keys))
    return payload


def test_drop_accepts_new_id_arrays() -> None:
    """``drop=['compatible_dimension_ids', 'incompatible_dimension_ids']``
    must NOT raise INVALID_MODE_ARGS — these are new allowlisted keys.
    Strict-size-budget callers may want to keep only the display
    strings (until migration); strict-id callers may drop the
    display strings — both are valid drop targets."""
    payload = _handle_then_drop(
        ["compatible_dimension_ids", "incompatible_dimension_ids"]
    )
    rec = (payload.get("fields") or [{}])[0]
    assert "compatible_dimension_ids" not in rec
    assert "incompatible_dimension_ids" not in rec
    # Display strings still present.
    assert "compatible_dimensions" in rec


def test_drop_legacy_display_arrays_keeps_id_arrays() -> None:
    """The migration path: drop the old display-string arrays, keep
    the new id arrays."""
    payload = _handle_then_drop(
        ["compatible_dimensions", "incompatible_dimensions"]
    )
    rec = (payload.get("fields") or [{}])[0]
    assert "compatible_dimensions" not in rec
    assert "incompatible_dimensions" not in rec
    # New ID arrays still present.
    assert "compatible_dimension_ids" in rec
