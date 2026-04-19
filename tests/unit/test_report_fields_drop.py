"""Tests for the ``drop`` response-shaping parameter on report_fields.

Covers acceptance criteria for the ``drop`` add-on:

- ``drop=None`` / omitted → byte-identical response to today (regression fence).
- ``drop=[<key>, ...]`` → named keys absent from every field record.
- Required keys (e.g. ``field_id``) → silently honored (per documented contract).
- Unknown keys → silently ignored (forward-compatible).
- Oversize drop list → ``INVALID_INPUT_SIZE`` (matches other list caps).
- Validate-mode response is unaffected (no field records to shape).
- Byte-cap measurement factors drop in (drop avoids needless description
  clipping when the post-drop payload fits under the cap).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from amazon_ads_mcp.tools import report_fields_v1_catalog as catalog_mod
from amazon_ads_mcp.tools.report_fields_errors import ReportFieldsErrorCode
from amazon_ads_mcp.tools.report_fields_v1_handler import (
    ReportFieldsToolError,
    _apply_drop_to_payload,
    handle,
)


# ---------- shared fixture: a small, known catalog with compat data ----------


@pytest.fixture
def small_catalog(tmp_path: Path):
    """Catalog with metric records that carry compatibility lists.

    Mirrors the production shape: metric records carry source-side
    ``compatible_dimensions`` / ``incompatible_dimensions`` (display
    labels), which is exactly the case the ``drop`` parameter is built
    to shrink. Two metrics + two dims is enough to exercise filtering,
    pagination, and per-entry key removal across listing and detail
    paths.
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
            "compatible_dimensions": [],
            "incompatible_dimensions": [],
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
    # Metric records that carry meaningful compat lists — these are what
    # ``drop`` is intended to remove.
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
            "compatible_dimensions": ["Campaign", "Ad group", "Search term"],
            "incompatible_dimensions": ["Day of week"],
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
            "compatible_dimensions": ["Campaign", "Ad group"],
            "incompatible_dimensions": [],
            "v3_name_dsp": "impressions",
            "v3_name_sponsored_ads": "impressions",
            "source": {"md_file": "imps.md", "parsed_at": "2026-04-18T00:00:00Z"},
        },
    ]

    def _write_sorted(path: Path, obj):
        path.write_bytes(
            json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False).encode()
            + b"\n"
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
        "source_files_sha256": {
            "amazon_ads_v1_dimensions.json": "x",
            "amazon_ads_v1_metrics.json": "y",
        },
        "output_files_sha256": {
            "dimensions.json": hashlib.sha256(
                (tmp_path / "dimensions.json").read_bytes()
            ).hexdigest(),
            "metrics.json": hashlib.sha256(
                (tmp_path / "metrics.json").read_bytes()
            ).hexdigest(),
            "dimension_label_index.json": hashlib.sha256(
                (tmp_path / "dimension_label_index.json").read_bytes()
            ).hexdigest(),
        },
    }
    (tmp_path / "catalog_meta.json").write_text(
        json.dumps(meta, indent=2, sort_keys=True)
    )

    catalog_mod.set_catalog_dir(tmp_path)
    yield tmp_path
    catalog_mod.set_catalog_dir(None)


# ---------- helpers ---------------------------------------------------------


def _wire_payload(response, *, drop=None) -> dict:
    """Mirror what the FastMCP wrapper emits to clients."""
    payload = response.model_dump(exclude_none=True)
    if drop:
        _apply_drop_to_payload(payload, set(drop))
    return payload


def _wire_bytes(response, *, drop=None) -> int:
    return len(json.dumps(_wire_payload(response, drop=drop)).encode("utf-8"))


# ---------- byte-identical regression --------------------------------------


def test_drop_none_is_byte_identical_to_default(small_catalog):
    """Caller who doesn't pass drop must see the exact same wire bytes.

    Acceptance criterion: ``drop=[]`` or omitted → byte-identical response
    to today. Any drift on the no-drop rows is a regression and blocks
    the change.
    """
    baseline = handle(mode="query", category="metric")
    with_explicit_none = handle(mode="query", category="metric", drop=None)
    with_empty_list = handle(mode="query", category="metric", drop=[])

    assert _wire_bytes(baseline) == _wire_bytes(with_explicit_none)
    assert _wire_bytes(baseline) == _wire_bytes(with_empty_list)
    assert _wire_payload(baseline) == _wire_payload(with_explicit_none)
    assert _wire_payload(baseline) == _wire_payload(with_empty_list)


def test_drop_none_detail_lookup_byte_identical(small_catalog):
    """Same regression fence on the fields=[...] detail-lookup path."""
    baseline = handle(mode="query", fields=["metric.clicks"])
    with_explicit_none = handle(mode="query", fields=["metric.clicks"], drop=None)
    assert _wire_bytes(baseline) == _wire_bytes(with_explicit_none)


# ---------- key absence on the wire ----------------------------------------


def test_drop_compat_arrays_removes_keys_from_every_record(small_catalog):
    """Dropped keys are absent from the wire JSON, not null-valued.

    Verifies the per-entry contract: when caller drops a key, every
    record is shaped consistently across the response.
    """
    response = handle(
        mode="query",
        category="metric",
        drop=["compatible_dimensions", "incompatible_dimensions"],
    )
    # _wire_payload mirrors what the FastMCP wrapper emits to clients.
    payload = _wire_payload(
        response, drop=["compatible_dimensions", "incompatible_dimensions"]
    )

    assert payload["fields"], "expected at least one record in fixture"
    for entry in payload["fields"]:
        assert "compatible_dimensions" not in entry, entry
        assert "incompatible_dimensions" not in entry, entry


def test_drop_unknown_key_raises_invalid_mode_args(small_catalog):
    """Unknown keys in drop fail loud with INVALID_MODE_ARGS.

    Strict validation surfaces typos like
    ``drop=["compatable_dimensions"]`` instead of silently keeping the
    bytes the caller intended to strip. The error message lists the
    allowed keys so the caller can self-correct.
    """
    with pytest.raises(ReportFieldsToolError) as excinfo:
        handle(mode="query", category="metric", drop=["totally_made_up_key"])
    assert excinfo.value.code == ReportFieldsErrorCode.INVALID_MODE_ARGS
    assert "totally_made_up_key" in str(excinfo.value)
    # Error message should include the allowlist so callers can self-correct.
    assert "compatible_dimensions" in str(excinfo.value)


def test_drop_typo_does_not_silently_strip_intended_key(small_catalog):
    """The exact concrete failure the strict-validation tweak prevents.

    Caller misspells ``compatible_dimensions``; without strict
    validation the typo is silent, the compat array stays, and the
    caller sees no byte savings without knowing why. With strict
    validation, the error names the typo.
    """
    with pytest.raises(ReportFieldsToolError) as excinfo:
        handle(
            mode="query",
            category="metric",
            drop=["compatable_dimensions"],  # missing 'i'
        )
    assert excinfo.value.code == ReportFieldsErrorCode.INVALID_MODE_ARGS


def test_drop_required_key_is_allowed_when_in_record_model(small_catalog):
    """Required keys are still removable as long as they're real record keys.

    The allowlist gates known vs unknown, not required vs optional —
    callers retain the freedom to strip any record key they own the
    consequences of, but only ones the model actually defines.
    """
    response = handle(mode="query", category="metric", drop=["field_id"])
    payload = _wire_payload(response, drop=["field_id"])
    for entry in payload["fields"]:
        assert "field_id" not in entry


def test_drop_top_level_metadata_key_is_rejected(small_catalog):
    """Top-level response keys (e.g. parsed_at) aren't record keys.

    Before strict validation these were silently ignored; now they
    raise so callers learn the boundary (drop shapes records, not
    response envelope).
    """
    with pytest.raises(ReportFieldsToolError) as excinfo:
        handle(
            mode="query",
            category="metric",
            drop=["compatible_dimensions", "parsed_at"],
        )
    assert excinfo.value.code == ReportFieldsErrorCode.INVALID_MODE_ARGS
    assert "parsed_at" in str(excinfo.value)


def test_drop_only_affects_field_records_not_envelope(small_catalog):
    """Sanity: legitimate drop values don't strip top-level metadata."""
    drop = ["compatible_dimensions", "incompatible_dimensions"]
    response = handle(mode="query", category="metric", drop=drop)
    payload = _wire_payload(response, drop=drop)
    assert "total_matching" in payload
    assert "parsed_at" in payload


# ---------- savings ---------------------------------------------------------


def test_drop_compat_arrays_yields_smaller_payload(small_catalog):
    """Dropping populated compat arrays measurably shrinks the wire payload."""
    baseline = handle(mode="query", category="metric")
    response = handle(
        mode="query",
        category="metric",
        drop=["compatible_dimensions", "incompatible_dimensions"],
    )
    baseline_bytes = _wire_bytes(baseline)
    smaller_bytes = _wire_bytes(
        response, drop=["compatible_dimensions", "incompatible_dimensions"]
    )
    assert smaller_bytes < baseline_bytes, (baseline_bytes, smaller_bytes)


# ---------- byte-cap interaction -------------------------------------------


def test_drop_avoids_truncation_when_compat_alone_would_overflow(
    small_catalog, monkeypatch
):
    """Byte cap is computed against the post-drop shape.

    With a tight cap, the default (no-drop) response must clip
    descriptions to fit; with the compat arrays dropped, the same
    request fits cleanly and stays untruncated. This is the whole
    reason byte-cap measurement is plumbed through to the handler
    rather than applied only at the wrapper.

    The cap is picked dynamically between the two payload sizes so the
    test stays robust if the fixture grows or shrinks. The drop set is
    chosen to remove the bulk of the bytes (compat arrays).
    """
    drop_keys = ["compatible_dimensions", "incompatible_dimensions"]

    # Use a high cap to measure the natural sizes without truncation effects.
    monkeypatch.setenv("LIST_REPORT_FIELDS_MAX_BYTES", "1000000")
    natural_no_drop = _wire_bytes(handle(mode="query", category="metric"))
    natural_with_drop = _wire_bytes(
        handle(mode="query", category="metric", drop=drop_keys),
        drop=drop_keys,
    )
    assert natural_with_drop < natural_no_drop, (
        "fixture compat arrays are too small to demonstrate drop savings"
    )

    # Pick a cap strictly between the two sizes: forces clipping on the
    # default response, leaves the with-drop response untouched.
    cap = (natural_no_drop + natural_with_drop) // 2
    monkeypatch.setenv("LIST_REPORT_FIELDS_MAX_BYTES", str(cap))

    no_drop = handle(mode="query", category="metric")
    with_drop = handle(mode="query", category="metric", drop=drop_keys)

    assert no_drop.truncated is True, (
        f"cap={cap} no_drop_natural={natural_no_drop} "
        f"with_drop_natural={natural_with_drop}"
    )
    assert with_drop.truncated is False, (
        f"cap={cap} no_drop_natural={natural_no_drop} "
        f"with_drop_natural={natural_with_drop}"
    )


# ---------- validate-mode no-op -------------------------------------------


def test_validate_mode_with_drop_raises_invalid_mode_args(small_catalog):
    """drop in validate mode is a contract violation, not a silent no-op.

    Per the strict-by-default contract: validate-mode responses carry
    no field records to shape, so passing drop signals a caller mistake
    and must surface as an error rather than be silently dropped on the
    floor.
    """
    with pytest.raises(ReportFieldsToolError) as excinfo:
        handle(
            mode="validate",
            validate_fields=["metric.clicks"],
            drop=["compatible_dimensions"],
        )
    assert excinfo.value.code == ReportFieldsErrorCode.INVALID_MODE_ARGS
    msg = str(excinfo.value).lower()
    assert "drop" in msg
    assert "validate" in msg


def test_validate_mode_with_empty_drop_is_accepted(small_catalog):
    """Empty list is the same as omitted — no caller intent to strip."""
    handle(
        mode="validate",
        validate_fields=["metric.clicks"],
        drop=[],
    )


def test_query_mode_drop_alone_does_not_satisfy_filter_requirement(small_catalog):
    """drop is shaping, not filtering — it must not let callers skip filters.

    Otherwise `mode="query", drop=["..."]` with no filter would dump
    the full catalog, which is exactly what the existing
    "at least one of" check exists to prevent.
    """
    with pytest.raises(ReportFieldsToolError) as excinfo:
        handle(mode="query", drop=["compatible_dimensions"])
    assert excinfo.value.code == ReportFieldsErrorCode.INVALID_MODE_ARGS


# ---------- input-cap validation ------------------------------------------


def test_drop_list_over_cap_rejected(small_catalog):
    """drop over its size cap → INVALID_INPUT_SIZE (matches other list caps)."""
    too_many = [f"key_{i}" for i in range(21)]
    with pytest.raises(ReportFieldsToolError) as excinfo:
        handle(mode="query", category="metric", drop=too_many)
    assert excinfo.value.code == ReportFieldsErrorCode.INVALID_INPUT_SIZE


# ---------- helper sanity --------------------------------------------------


def test_apply_drop_to_payload_is_a_no_op_on_validate_shape():
    """_apply_drop_to_payload tolerates payloads with no `fields` array."""
    payload = {"mode": "validate", "valid": True, "unknown_fields": []}
    out = _apply_drop_to_payload(payload, {"anything"})
    assert out == payload
