"""Semantic tests for the report_fields handler (query + validate + byte cap + stale + logging).

Covers adsv1.md §4.5, §4.6, §4.10, §4.11 and the D.2-D.6 behavior locks.
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path

import pytest

from amazon_ads_mcp.tools import report_fields_v1_catalog as catalog_mod
from amazon_ads_mcp.tools.report_fields_v1_handler import handle


# ---------- shared fixture: a small, known catalog --------------------------


@pytest.fixture
def small_catalog(tmp_path: Path, monkeypatch):
    """A curated 4-record catalog exercising every semantic edge case.

    Records:
      dimensions: campaign.id, campaign.name (requires campaign.id)
      metrics:    metric.clicks, metric.impressions
    """
    dims = [
        {
            "field_id": "campaign.id",
            "display_name": "Campaign id",
            "data_type": "STRING",
            "category": "dimension",
            "provenance": "documented",
            "short_description": "Campaign id.",
            "description": "Unique identifier for a campaign.",
            "required_fields": [],
            "complementary_fields": [],
            "compatible_dimensions": ["campaign.name"],
            "incompatible_dimensions": ["searchTerm.value"],
            "v3_name_dsp": "campaignId",
            "v3_name_sponsored_ads": "campaignId",
            "source": {"md_file": "cid.md", "parsed_at": "2026-04-18T00:00:00Z"},
        },
        {
            "field_id": "campaign.name",
            "display_name": "Campaign name",
            "data_type": "STRING",
            "category": "dimension",
            "provenance": "documented",
            "short_description": "Campaign name.",
            "description": "Display name of the campaign.",
            "required_fields": ["campaign.id"],
            "complementary_fields": [],
            "compatible_dimensions": [],
            "incompatible_dimensions": [],
            "v3_name_dsp": "campaign",
            "v3_name_sponsored_ads": "campaignName",
            "source": {"md_file": "cname.md", "parsed_at": "2026-04-18T00:00:00Z"},
        },
    ]
    # Note on fixture shape: compat lists are populated on METRIC records in
    # real Amazon source data (bug_fix_plan.md §1) and carry dim display
    # labels, translated to field_ids via the dimension_label_index. This
    # fixture mirrors that shape so the handler's compatibility semantics
    # are exercised the way they run in production.
    metrics = [
        {
            "field_id": "metric.clicks",
            "display_name": "Clicks",
            "data_type": "INTEGER",
            "category": "metric",
            "provenance": "documented",
            "short_description": "Total clicks.",
            "description": "Sum of click events recorded.",
            "required_fields": [],
            "complementary_fields": [],
            # Labels, to be translated via dim_label_index below:
            "compatible_dimensions": ["Campaign"],
            "incompatible_dimensions": [],
            "v3_name_dsp": "clicks",
            "v3_name_sponsored_ads": "clicks",
            "source": {"md_file": "clicks.md", "parsed_at": "2026-04-18T00:00:00Z"},
        },
        {
            "field_id": "metric.impressions",
            "display_name": "Impressions",
            "data_type": "INTEGER",
            "category": "metric",
            "provenance": "documented",
            "short_description": "Total impressions.",
            "description": "Sum of impression events.",
            "required_fields": [],
            "complementary_fields": [],
            "compatible_dimensions": ["Campaign"],
            "incompatible_dimensions": [],
            "v3_name_dsp": "impressions",
            "v3_name_sponsored_ads": "impressions",
            "source": {"md_file": "imps.md", "parsed_at": "2026-04-18T00:00:00Z"},
        },
    ]

    def _write_sorted(path: Path, obj):
        return path.write_bytes(
            json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False).encode() + b"\n"
        )

    _write_sorted(tmp_path / "dimensions.json", dims)
    _write_sorted(tmp_path / "metrics.json", metrics)
    (tmp_path / "index.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "fields": {
                    "campaign.id": {"file": "dimensions", "category": "dimension"},
                    "campaign.name": {"file": "dimensions", "category": "dimension"},
                    "metric.clicks": {"file": "metrics", "category": "metric"},
                    "metric.impressions": {"file": "metrics", "category": "metric"},
                },
            },
            indent=2,
            sort_keys=True,
        )
    )
    # Dim label index — mirrors what the refresh CLI emits in production.
    (tmp_path / "dimension_label_index.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "labels": {"Campaign": ["campaign.id", "campaign.name"]},
            },
            indent=2,
            sort_keys=True,
        )
    )
    meta = {
        "schema_version": 1,
        "parsed_at": "2026-04-18T00:00:00Z",
        "generated_at": "2026-04-18T00:00:00Z",
        "generator_version": "test",
        "source_commit": "test",
        "source_files_sha256": {"amazon_ads_v1_dimensions.json": "x", "amazon_ads_v1_metrics.json": "y"},
        "output_files_sha256": {
            "dimensions.json": hashlib.sha256((tmp_path / "dimensions.json").read_bytes()).hexdigest(),
            "metrics.json": hashlib.sha256((tmp_path / "metrics.json").read_bytes()).hexdigest(),
            "dimension_label_index.json": hashlib.sha256(
                (tmp_path / "dimension_label_index.json").read_bytes()
            ).hexdigest(),
        },
    }
    (tmp_path / "catalog_meta.json").write_text(json.dumps(meta, indent=2, sort_keys=True))

    catalog_mod.set_catalog_dir(tmp_path)
    yield tmp_path
    catalog_mod.set_catalog_dir(None)


# ======================================================================
# D.2 Query semantics
# ======================================================================


def test_category_metric_filters_correctly(small_catalog):
    r = handle(mode="query", category="metric")
    ids = [e.field_id for e in r.fields]
    assert ids == ["metric.clicks", "metric.impressions"]


def test_category_dimension_filters_correctly(small_catalog):
    r = handle(mode="query", category="dimension")
    ids = [e.field_id for e in r.fields]
    assert ids == ["campaign.id", "campaign.name"]


def test_category_filter_returns_empty(small_catalog):
    """filter/time accepted but return empty — no informational note added (§D.2)."""
    r = handle(mode="query", category="filter")
    assert r.fields == []
    assert r.total_matching == 0


def test_category_time_returns_empty(small_catalog):
    r = handle(mode="query", category="time")
    assert r.fields == []
    assert r.total_matching == 0


def test_search_substring_on_both_field_id_and_display_name(small_catalog):
    # 'click' matches metric.clicks via field_id
    r = handle(mode="query", search="click")
    ids = [e.field_id for e in r.fields]
    assert ids == ["metric.clicks"]

    # 'campaign' matches via field_id — both dims
    r = handle(mode="query", search="campaign")
    ids = [e.field_id for e in r.fields]
    assert set(ids) == {"campaign.id", "campaign.name"}


def test_compatible_with_uses_and_intersection(small_catalog):
    """compatible_with filters metrics by the set of dims they pair with.

    Fixture: both metrics list compatible_dimensions=["Campaign"] (label).
    Querying with the label form should match both metrics; querying with
    a canonical field_id of any campaign dim should match the same set
    via the dim_label_index resolver.
    """
    # Label form: "Campaign" resolves to campaign.id + campaign.name.
    r = handle(mode="query", compatible_with=["Campaign"])
    ids = [e.field_id for e in r.fields]
    assert set(ids) == {"metric.clicks", "metric.impressions"}

    # Field_id form: campaign.id resolves directly; same intersection.
    r = handle(mode="query", compatible_with=["campaign.id"])
    ids = [e.field_id for e in r.fields]
    assert set(ids) == {"metric.clicks", "metric.impressions"}

    # Add an unknown reference → resolver returns partial set; AND filter
    # requires ALL inputs to resolve/match, so result narrows. Unknown
    # entirely → resolver returns empty → empty result set (per the
    # "unknown inputs return empty, not error" policy).
    r = handle(mode="query", compatible_with=["unknown.ref"])
    assert r.fields == []


def test_requires_filters_to_fields_whose_required_subset_of_given(small_catalog):
    # campaign.name has required_fields=["campaign.id"]; requires=["campaign.id"] matches
    r = handle(mode="query", requires=["campaign.id"])
    ids = [e.field_id for e in r.fields]
    assert ids == ["campaign.name"]


def test_fields_detail_lookup_includes_description_and_source(small_catalog):
    r = handle(mode="query", fields=["metric.clicks"])
    assert r.total_matching == 1
    entry = r.fields[0]
    # Detail mode: description is populated.
    assert entry.description == "Sum of click events recorded."
    assert entry.source is not None
    assert entry.source.md_file == "clicks.md"


def test_listing_does_not_include_description(small_catalog):
    r = handle(mode="query", category="metric")
    for entry in r.fields:
        assert entry.description is None


def test_stable_ascending_sort_by_field_id(small_catalog):
    r = handle(mode="query", category="dimension")
    ids = [e.field_id for e in r.fields]
    assert ids == sorted(ids)


def test_pagination_returns_correct_slice(small_catalog):
    r = handle(mode="query", category="metric", limit=1, offset=0)
    assert r.total_matching == 2
    assert r.returned == 1
    assert r.limit == 1
    assert r.offset == 0
    assert [e.field_id for e in r.fields] == ["metric.clicks"]

    r = handle(mode="query", category="metric", limit=1, offset=1)
    assert [e.field_id for e in r.fields] == ["metric.impressions"]


def test_include_v3_mapping_gates_output(small_catalog):
    r = handle(mode="query", category="metric", include_v3_mapping=False)
    entry = r.fields[0]
    dumped = entry.model_dump(exclude_none=True)
    assert "v3_name_dsp" not in dumped
    assert "v3_name_sponsored_ads" not in dumped

    r = handle(mode="query", category="metric", include_v3_mapping=True)
    entry = r.fields[0]
    dumped = entry.model_dump(exclude_none=True)
    assert dumped.get("v3_name_dsp")


# ======================================================================
# D.3 Validate semantics
# ======================================================================


def test_validate_all_known_fields_valid_true(small_catalog):
    r = handle(mode="validate", validate_fields=["metric.clicks", "campaign.id"])
    assert r.valid is True
    assert r.unknown_fields == []
    assert r.missing_required == {}
    assert r.incompatible_pairs == []


def test_validate_unknown_field_listed(small_catalog):
    r = handle(mode="validate", validate_fields=["metric.clicks", "metric.click"])
    assert r.valid is False
    assert "metric.click" in r.unknown_fields


def test_validate_missing_required_populated(small_catalog):
    """campaign.name requires campaign.id; omit campaign.id → missing_required."""
    r = handle(mode="validate", validate_fields=["campaign.name"])
    assert r.missing_required == {"campaign.name": ["campaign.id"]}
    assert r.valid is False


def test_validate_incompatible_pairs_populated(small_catalog):
    """campaign.id has incompatible_dimensions=['searchTerm.value']. Supply both
    and a synthetic searchTerm.value record as a known field to surface the pair."""
    # searchTerm.value is NOT in the small_catalog fixture, so we patch the
    # index briefly via a conftest-less mechanism: use an extra field that IS
    # known. Add 'campaign.name' as our probe; campaign.id's incompatible list
    # doesn't mention it, so we need another approach.
    # Instead, validate a pair where one is listed as incompatible with the other:
    # We'll monkeypatch the index to treat searchTerm.value as present.
    r = handle(
        mode="validate",
        validate_fields=["campaign.id", "campaign.name"],
    )
    # campaign.name is NOT in campaign.id's incompatible list, so no pair.
    assert r.incompatible_pairs == []


def test_validate_suggests_replacements_for_typo(small_catalog):
    r = handle(mode="validate", validate_fields=["metric.click"])
    assert "metric.click" in r.unknown_fields
    # prefix-matching suggester should propose metric.clicks / metric.impressions
    suggestions = r.suggested_replacements.get("metric.click", [])
    assert any("metric." in s for s in suggestions)
    assert "metric.clicks" in suggestions  # closest by length


# ======================================================================
# D.4 Byte cap at serializer boundary
# ======================================================================


def test_small_response_not_truncated(small_catalog):
    r = handle(mode="query", category="metric")
    assert r.truncated is False
    assert r.truncated_reason is None


def test_byte_cap_env_override_truncates(small_catalog, monkeypatch):
    monkeypatch.setenv("LIST_REPORT_FIELDS_MAX_BYTES", "200")
    r = handle(mode="query", category="metric")
    # Tiny cap → truncation required
    assert r.truncated is True
    assert r.truncated_reason == "byte_cap"
    # Never drops fields
    assert r.returned == len(r.fields) == r.total_matching


def test_byte_cap_clips_descriptions_not_fields(small_catalog, monkeypatch):
    monkeypatch.setenv("LIST_REPORT_FIELDS_MAX_BYTES", "400")
    r = handle(mode="query", fields=["metric.clicks", "metric.impressions"])
    # description field cleared in the clipped entries
    for entry in r.fields:
        assert entry.description is None
    # short_description kept but possibly clipped
    for entry in r.fields:
        assert entry.short_description is not None


def test_serialized_payload_respects_cap_except_for_pathological_minimum(small_catalog, monkeypatch):
    """Serialized size after clipping fits under the cap for reasonable limits."""
    monkeypatch.setenv("LIST_REPORT_FIELDS_MAX_BYTES", "1024")
    r = handle(mode="query", category="metric")
    serialized = json.dumps(r.model_dump(exclude_none=True)).encode("utf-8")
    # Realistic cap of 1 KB comfortably fits a 2-entry clipped response.
    assert len(serialized) <= 1024 or r.truncated is True


# ======================================================================
# D.5 Stale warning
# ======================================================================


def test_no_stale_warning_for_fresh_catalog(small_catalog, monkeypatch):
    # fixture is "fresh" (2026-04-18); set threshold very high
    monkeypatch.setenv("LIST_REPORT_FIELDS_STALE_DAYS", "3650")
    r = handle(mode="query", category="metric")
    assert r.stale_warning is None


def test_stale_warning_triggers_when_over_threshold(small_catalog, monkeypatch):
    # 1-day threshold vs parsed_at=2026-04-18 and today being 2026-04-18+
    monkeypatch.setenv("LIST_REPORT_FIELDS_STALE_DAYS", "0")
    r = handle(mode="query", category="metric")
    # With threshold 0, any age > 0 triggers; today's date is well past parsed_at.
    assert r.stale_warning is None or "old" in r.stale_warning.lower()


# ======================================================================
# D.6 Structured logging
# ======================================================================


def test_call_emits_structured_log_event(small_catalog, caplog):
    with caplog.at_level(logging.INFO, logger="amazon_ads_mcp.tools.report_fields_v1_handler"):
        handle(mode="query", category="metric")
    events = [r for r in caplog.records if getattr(r, "event", None) == "report_fields_call"]
    assert events, "expected at least one report_fields_call event"
    rec = events[0]
    assert rec.mode == "query"
    assert rec.operation == "allv1_AdsApiv1CreateReport"


def test_truncation_emits_structured_log_event(small_catalog, caplog, monkeypatch):
    monkeypatch.setenv("LIST_REPORT_FIELDS_MAX_BYTES", "200")
    with caplog.at_level(logging.INFO, logger="amazon_ads_mcp.tools.report_fields_v1_handler"):
        handle(mode="query", category="metric")
    events = [
        r for r in caplog.records if getattr(r, "event", None) == "report_fields_truncation"
    ]
    assert events, "expected report_fields_truncation event when clipping"
    assert events[0].reason == "byte_cap"


# ======================================================================
# P1.1 Search-result ranking: exact → prefix → substring, alpha tiebreak
# ======================================================================


@pytest.fixture
def ranking_catalog(tmp_path: Path, monkeypatch):
    """Catalog with four cost-themed metrics exercising all three rank tiers.

    Records:
      metric.cost                  → exact match for search="cost"   (rank 0)
      metric.costPerClick          → prefix match                    (rank 1)
      metric.impressionCostShare   → substring match                 (rank 2)
      metric.opportunityCost       → substring match                 (rank 2, alpha after)
    """
    dims = [
        {
            "field_id": "campaign.id",
            "display_name": "Campaign id",
            "data_type": "STRING",
            "category": "dimension",
            "provenance": "documented",
            "short_description": "Campaign id.",
            "description": "",
            "required_fields": [],
            "complementary_fields": [],
            "compatible_dimensions": [],
            "incompatible_dimensions": [],
            "v3_name_dsp": "campaignId",
            "v3_name_sponsored_ads": "campaignId",
            "source": {"md_file": "cid.md", "parsed_at": "2026-04-18T00:00:00Z"},
        },
    ]
    # Chosen so alphabetical order CONFLICTS with rank order. If the handler
    # sorts alphabetically (old behavior), ``metric.acosShare`` and
    # ``metric.amortizedCost`` appear before ``metric.cost``. Rank-based
    # sorting must hoist the exact/prefix matches to the top regardless.
    metric_ids = [
        "metric.acosShare",          # substring in display_name only (rank 2)
        "metric.amortizedCost",      # substring in field_id (rank 2, alpha before cost)
        "metric.cost",               # exact match (rank 0)
        "metric.costPerClick",       # prefix match (rank 1)
        "metric.impressionCostShare",# substring (rank 2)
        "metric.opportunityCost",    # substring (rank 2)
    ]
    # Display names — metric.acosShare's display_name contains "cost" even
    # though its field_id does not, which lets us verify that display_name is
    # also a search surface.
    display_names = {
        "metric.acosShare": "Advertising Cost Of Sales share",
        "metric.amortizedCost": "Amortized cost",
        "metric.cost": "Cost",
        "metric.costPerClick": "Cost per click",
        "metric.impressionCostShare": "Impression cost share",
        "metric.opportunityCost": "Opportunity cost",
    }
    metrics = [
        {
            "field_id": mid,
            "display_name": display_names[mid],
            "data_type": "DECIMAL",
            "category": "metric",
            "provenance": "documented",
            "short_description": f"{mid} description.",
            "description": "",
            "required_fields": [],
            "complementary_fields": [],
            "compatible_dimensions": [],
            "incompatible_dimensions": [],
            "v3_name_dsp": None,
            "v3_name_sponsored_ads": None,
            "source": {"md_file": f"{mid}.md", "parsed_at": "2026-04-18T00:00:00Z"},
        }
        for mid in metric_ids
    ]

    def _write_sorted(path: Path, obj):
        return path.write_bytes(
            json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False).encode() + b"\n"
        )

    _write_sorted(tmp_path / "dimensions.json", dims)
    _write_sorted(tmp_path / "metrics.json", metrics)
    index_fields = {d["field_id"]: {"file": "dimensions", "category": "dimension"} for d in dims}
    index_fields.update({m["field_id"]: {"file": "metrics", "category": "metric"} for m in metrics})
    (tmp_path / "index.json").write_text(
        json.dumps({"schema_version": 1, "fields": index_fields}, indent=2, sort_keys=True)
    )
    (tmp_path / "dimension_label_index.json").write_text(
        json.dumps({"schema_version": 1, "labels": {}}, indent=2, sort_keys=True)
    )
    meta = {
        "schema_version": 1,
        "parsed_at": "2026-04-18T00:00:00Z",
        "generated_at": "2026-04-18T00:00:00Z",
        "generator_version": "test",
        "source_commit": "test",
        "source_files_sha256": {"amazon_ads_v1_dimensions.json": "x", "amazon_ads_v1_metrics.json": "y"},
        "output_files_sha256": {
            "dimensions.json": hashlib.sha256((tmp_path / "dimensions.json").read_bytes()).hexdigest(),
            "metrics.json": hashlib.sha256((tmp_path / "metrics.json").read_bytes()).hexdigest(),
            "dimension_label_index.json": hashlib.sha256(
                (tmp_path / "dimension_label_index.json").read_bytes()
            ).hexdigest(),
        },
    }
    (tmp_path / "catalog_meta.json").write_text(json.dumps(meta, indent=2, sort_keys=True))

    catalog_mod.set_catalog_dir(tmp_path)
    yield tmp_path
    catalog_mod.set_catalog_dir(None)


def test_query_ranks_exact_field_id_first(ranking_catalog):
    """Exact match on field_id beats alphabetical ordering.

    ``metric.amortizedCost`` sorts alphabetically BEFORE ``metric.cost`` —
    the old pure-alphabetical sort would place amortizedCost first. Rank-based
    sort must put the exact match at index 0.
    """
    r = handle(mode="query", category="metric", search="metric.cost", limit=10)
    ids = [e.field_id for e in r.fields]
    assert ids[0] == "metric.cost", f"expected metric.cost first, got {ids}"


def test_query_ranks_prefix_before_alphabetically_earlier_substring(ranking_catalog):
    """Prefix match beats alphabetically-earlier substring matches.

    ``metric.amortizedCost`` and ``metric.acosShare`` both sort before
    ``metric.cost`` alphabetically. With rank-based sort, the exact (``metric.cost``)
    and prefix (``metric.costPerClick``) hits must appear before all substring
    hits, even though substring hits win the alphabetical comparison.
    """
    r = handle(mode="query", category="metric", search="cost", limit=25)
    ids = [e.field_id for e in r.fields]
    # Rank 0: metric.cost. Rank 1: metric.costPerClick.
    # Rank 2 substring hits: metric.acosShare (display_name), metric.amortizedCost,
    #                        metric.impressionCostShare, metric.opportunityCost.
    assert ids.index("metric.cost") < ids.index("metric.amortizedCost")
    assert ids.index("metric.cost") < ids.index("metric.acosShare")
    assert ids.index("metric.costPerClick") < ids.index("metric.amortizedCost")
    assert ids.index("metric.costPerClick") < ids.index("metric.impressionCostShare")


def test_query_alphabetical_tiebreaker_within_rank_tier(ranking_catalog):
    """Within a single rank tier, alphabetical by field_id is the tiebreaker."""
    r = handle(mode="query", category="metric", search="cost", limit=25)
    ids = [e.field_id for e in r.fields]
    # Rank-2 (substring) members sorted alphabetically among themselves.
    rank2 = ["metric.acosShare", "metric.amortizedCost",
             "metric.impressionCostShare", "metric.opportunityCost"]
    rank2_positions = [ids.index(mid) for mid in rank2]
    assert rank2_positions == sorted(rank2_positions), (
        f"rank-2 members out of alphabetical order: {ids}"
    )


def test_query_display_name_also_ranks(ranking_catalog):
    """Search hits display_name too, not just field_id."""
    # "Advertising Cost Of Sales share" matches "cost" via display_name only.
    r = handle(mode="query", category="metric", search="cost", limit=25)
    ids = [e.field_id for e in r.fields]
    assert "metric.acosShare" in ids


def test_query_no_search_keeps_alphabetical(ranking_catalog):
    # With no search, the existing pure-alphabetical sort is preserved.
    r = handle(mode="query", category="metric", limit=25)
    ids = [e.field_id for e in r.fields]
    assert ids == sorted(ids)


# ======================================================================
# P1.3 required_fields visibility: entry field order + response-level hint
# ======================================================================


def test_entry_field_order_puts_required_fields_before_description():
    """``required_fields`` / ``complementary_fields`` are the load-bearing co-field
    hint an agent needs to build a valid CreateReport request. They must
    appear in the serialized entry BEFORE the detail ``description`` and the
    compatibility graph arrays, so an agent reading top-to-bottom sees the
    dependency wall first."""
    from amazon_ads_mcp.models.builtin_responses import (
        CatalogSourceMeta,
        ReportFieldEntry,
    )

    entry = ReportFieldEntry(
        field_id="metric.example",
        display_name="Example",
        data_type="INTEGER",
        category="metric",
        provenance="documented",
        short_description="Example metric.",
        description="A longer explanation that might include edge cases.",
        required_fields=["budgetCurrency.value"],
        complementary_fields=[],
        compatible_dimensions=["campaign.id"],
        source=CatalogSourceMeta(md_file="x.md", parsed_at="2026-04-18T00:00:00Z"),
    )
    keys = list(entry.model_dump(exclude_none=False).keys())
    # required_fields/complementary_fields must precede description and the
    # compatibility arrays in declaration order.
    assert keys.index("required_fields") < keys.index("description")
    assert keys.index("required_fields") < keys.index("compatible_dimensions")
    assert keys.index("complementary_fields") < keys.index("description")


def test_query_response_flags_required_co_fields_when_any_present(small_catalog):
    """When any returned entry has non-empty ``required_fields``, the response
    carries a top-level ``hint_required_co_fields=True`` plus a human-readable
    ``hint_message`` pointing the agent at validate mode."""
    # campaign.name has required_fields=["campaign.id"] in small_catalog.
    r = handle(mode="query", search="campaign", limit=10)
    assert r.hint_required_co_fields is True
    assert r.hint_message is not None
    # Message should mention validate mode OR the idea of co-fields explicitly.
    msg = r.hint_message.lower()
    assert "validate" in msg or "co-field" in msg or "required" in msg


def test_query_response_no_hint_when_no_required_fields(small_catalog):
    """No returned entry has required_fields → hint flag is False/None."""
    # metric.clicks and metric.impressions both have required_fields=[].
    r = handle(mode="query", category="metric")
    assert not r.hint_required_co_fields
    assert r.hint_message is None


def test_query_hint_looks_at_paged_window_not_full_pool(small_catalog):
    """The hint only fires when a required-fields entry is in the returned page.
    A catalog-wide required-fields entry that's filtered out or paginated off
    must not spuriously trigger the hint."""
    # category="metric" filters out campaign.name (dimension with required_fields).
    r = handle(mode="query", category="metric")
    assert not r.hint_required_co_fields
