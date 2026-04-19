"""Regression tests for the real-data compatibility graph (bug_fix_plan.md §1).

These tests pin the failing probes the tester surfaced against the real
packaged catalog. They load the actual shipped artifacts — no fixtures —
so any regression that drops compat data shows up immediately.
"""

from __future__ import annotations

import pytest

from amazon_ads_mcp.tools import report_fields_v1_catalog as catalog_mod
from amazon_ads_mcp.tools.report_fields_v1_handler import handle


@pytest.fixture(autouse=True)
def _reset_catalog():
    """Drop any test-only override so these tests run against the real
    packaged catalog under src/amazon_ads_mcp/resources/adsv1/."""
    catalog_mod.set_catalog_dir(None)
    yield
    catalog_mod.set_catalog_dir(None)


# ---------- Issue 10 — compatibility data populated end-to-end -------------


def test_metric_record_carries_compat_lists():
    """Every metric in the packaged catalog must carry non-empty
    compatible_dimensions (source has 700/700 populated)."""
    metrics = catalog_mod.get_metrics()
    assert metrics, "no metrics loaded"
    populated = sum(1 for r in metrics if r.get("compatible_dimensions"))
    fraction = populated / len(metrics)
    assert fraction >= 0.95, (
        f"compatible_dimensions populated on only {fraction:.1%} of metrics; "
        "refresh likely dropped the data"
    )


def test_dimension_record_carries_inverted_compat_metrics():
    """Dimensions don't carry compat data in source (0/118). The refresh
    pipeline must build an inverted `compatible_metrics` list from the
    metric side so the graph is queryable from either direction."""
    dims = catalog_mod.get_dimensions()
    assert dims, "no dimensions loaded"
    populated = sum(1 for r in dims if r.get("compatible_metrics"))
    fraction = populated / len(dims)
    assert fraction >= 0.5, (
        f"compatible_metrics inverted index populated on only {fraction:.1%} "
        "of dimensions; inverted-index builder is broken"
    )


def test_query_compatible_with_field_id_form_returns_metrics():
    """compatible_with=['searchTerm.value'] must return ≥1 metric."""
    r = handle(mode="query", compatible_with=["searchTerm.value"], limit=10)
    assert r.total_matching >= 1, (
        "compatible_with using canonical field_id form returned no metrics; "
        "handler filter walks the wrong side of the relation"
    )


def test_query_compatible_with_label_form_returns_same_set():
    """Issue 12: display-label form must produce the same result set as
    the canonical field_id form."""
    by_label = handle(mode="query", compatible_with=["Search term"], limit=100)
    by_id = handle(mode="query", compatible_with=["searchTerm.value"], limit=100)
    assert by_label.total_matching == by_id.total_matching, (
        f"label form matched {by_label.total_matching}, id form matched "
        f"{by_id.total_matching}; label→field_id resolver is broken"
    )


def test_query_compatible_with_unknown_returns_empty():
    r = handle(mode="query", compatible_with=["NotARealLabel"], limit=10)
    assert r.total_matching == 0


def test_query_compatible_with_ad_label_returns_metrics():
    """Pin the tester's exact failing probe: compatible_with=['Ad']."""
    r = handle(mode="query", compatible_with=["Ad"], limit=10)
    assert r.total_matching >= 1, (
        "compatible_with=['Ad'] returned 0 metrics — must match all metrics "
        "that list 'Ad' in their compatible_dimensions"
    )


# ---------- Issue 10 — validate mode incompatible pairs ------------------


def test_validate_incompatible_pairs_detected():
    """validate mode must surface at least one incompatible pair when given
    a field list whose members include cross-incompatible entries in source."""
    # metric.combinedPurchases references incompatible dimensions; pick a
    # real metric + a real dimension field id that conflict per source data.
    # We don't hard-code the pair — we probe: for any metric that has a
    # non-empty incompatible_dimensions, validate should surface at least
    # one pair when both the metric and one of its incompatibles are
    # submitted. The handler takes field_id input; the incompatibles are
    # labels → we rely on the resolver (Issue 12) to translate.
    metrics = catalog_mod.get_metrics()
    sample = next(
        (m for m in metrics if m.get("incompatible_dimensions")),
        None,
    )
    assert sample is not None, "no metric carries incompatible_dimensions"

    label_idx = catalog_mod.get_dimension_label_index()
    # Find the first incompatible label that resolves to a field_id.
    conflict_field_id = None
    for label in sample["incompatible_dimensions"]:
        fids = label_idx.get(label, [])
        if fids:
            conflict_field_id = fids[0]
            break
    assert conflict_field_id is not None, (
        "no resolvable conflict label for sampled metric"
    )

    r = handle(
        mode="validate",
        operation="allv1_AdsApiv1CreateReport",
        validate_fields=[sample["field_id"], conflict_field_id],
    )
    assert r.incompatible_pairs, (
        f"expected incompatible pair for ({sample['field_id']}, "
        f"{conflict_field_id}); got {r.incompatible_pairs}"
    )


# ---------- Issue 11 — suggester finds obvious matches -------------------


def test_suggest_replacements_finds_totalcost_for_cost():
    """metric.cost → metric.totalCost must be in suggested_replacements."""
    r = handle(
        mode="validate",
        operation="allv1_AdsApiv1CreateReport",
        validate_fields=["metric.cost"],
    )
    suggestions = r.suggested_replacements.get("metric.cost", [])
    assert "metric.totalCost" in suggestions, (
        f"metric.cost should suggest metric.totalCost; got {suggestions}"
    )
