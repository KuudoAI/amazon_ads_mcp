"""Tests for the report_fields Pydantic response models.

Contract from adsv1.md §4.5: every new model uses `extra="forbid"`, the
response union is tagged on `mode`, category-conditional lists default to
None so the serializer drops them via `exclude_none=True`, and always-
applicable lists default to [] and always emit.
"""


import pytest
from pydantic import TypeAdapter, ValidationError

from amazon_ads_mcp.models.builtin_responses import (
    CatalogSourceMeta,
    QueryReportFieldsResponse,
    ReportFieldEntry,
    ReportFieldsResponse,
    ValidateReportFieldsResponse,
)


# ---------- CatalogSourceMeta ------------------------------------------------


def test_catalog_source_meta_forbids_extras():
    with pytest.raises(ValidationError):
        CatalogSourceMeta(md_file="x.md", parsed_at="2026-01-01T00:00:00Z", sneaky=1)


def test_catalog_source_meta_happy():
    m = CatalogSourceMeta(md_file="x.md", parsed_at="2026-01-01T00:00:00Z")
    assert m.md_file == "x.md"
    assert m.parsed_at == "2026-01-01T00:00:00Z"


# ---------- ReportFieldEntry -------------------------------------------------


def _entry_kwargs(**overrides):
    base = dict(
        field_id="metric.clicks",
        display_name="Clicks",
        data_type="INTEGER",
        category="metric",
        provenance="documented",
        short_description="Number of clicks.",
    )
    base.update(overrides)
    return base


def test_entry_forbids_extras():
    with pytest.raises(ValidationError):
        ReportFieldEntry(**_entry_kwargs(sneaky="nope"))


def test_entry_provenance_restricted():
    with pytest.raises(ValidationError):
        ReportFieldEntry(**_entry_kwargs(provenance="hearsay"))


def test_entry_category_restricted():
    with pytest.raises(ValidationError):
        ReportFieldEntry(**_entry_kwargs(category="fruit"))


def test_entry_always_applicable_lists_default_empty_and_emit():
    """required_fields and complementary_fields default [] and ALWAYS emit."""
    e = ReportFieldEntry(**_entry_kwargs())
    dump = e.model_dump(exclude_none=True)
    assert dump["required_fields"] == []
    assert dump["complementary_fields"] == []


def test_entry_category_conditional_lists_default_none_and_drop():
    """compatible_dimensions / incompatible_dimensions default None, drop from output."""
    e = ReportFieldEntry(**_entry_kwargs())
    dump = e.model_dump(exclude_none=True)
    assert "compatible_dimensions" not in dump
    assert "incompatible_dimensions" not in dump


def test_entry_category_conditional_lists_emit_when_populated():
    e = ReportFieldEntry(
        **_entry_kwargs(
            category="dimension",
            compatible_dimensions=["campaign.id"],
            incompatible_dimensions=["searchTerm.value"],
        )
    )
    dump = e.model_dump(exclude_none=True)
    assert dump["compatible_dimensions"] == ["campaign.id"]
    assert dump["incompatible_dimensions"] == ["searchTerm.value"]


def test_entry_source_uses_typed_submodel():
    e = ReportFieldEntry(
        **_entry_kwargs(
            source=CatalogSourceMeta(md_file="clicks.md", parsed_at="2026-01-01T00:00:00Z")
        )
    )
    assert isinstance(e.source, CatalogSourceMeta)


def test_entry_source_forbids_dict_with_extras():
    """source is a CatalogSourceMeta, not a free-form dict — no silent extras."""
    with pytest.raises(ValidationError):
        ReportFieldEntry(
            **_entry_kwargs(
                source={
                    "md_file": "x.md",
                    "parsed_at": "2026-01-01T00:00:00Z",
                    "sneaky": "dropped",
                }
            )
        )


# ---------- QueryReportFieldsResponse ----------------------------------------


def _query_kwargs(**overrides):
    base = dict(
        mode="query",
        success=True,
        operation="allv1_AdsApiv1CreateReport",
        catalog_schema_version=1,
        parsed_at="2026-04-18T17:20:49Z",
        total_matching=0,
        returned=0,
        offset=0,
        limit=25,
        fields=[],
    )
    base.update(overrides)
    return base


def test_query_response_mode_required_literal():
    with pytest.raises(ValidationError):
        QueryReportFieldsResponse(**_query_kwargs(mode="validate"))


def test_query_response_forbids_extras():
    with pytest.raises(ValidationError):
        QueryReportFieldsResponse(**_query_kwargs(sneaky="dropped"))


def test_query_response_truncated_reason_restricted():
    with pytest.raises(ValidationError):
        QueryReportFieldsResponse(
            **_query_kwargs(truncated=True, truncated_reason="shrug")
        )


def test_query_response_truncated_reason_literals():
    for reason in ("byte_cap", "limit", "field_filter"):
        r = QueryReportFieldsResponse(
            **_query_kwargs(truncated=True, truncated_reason=reason)
        )
        assert r.truncated_reason == reason


# ---------- ValidateReportFieldsResponse -------------------------------------


def _validate_kwargs(**overrides):
    base = dict(
        mode="validate",
        success=True,
        operation="allv1_AdsApiv1CreateReport",
        valid=True,
        unknown_fields=[],
        missing_required={},
        incompatible_pairs=[],
        suggested_replacements={},
    )
    base.update(overrides)
    return base


def test_validate_response_mode_required_literal():
    with pytest.raises(ValidationError):
        ValidateReportFieldsResponse(**_validate_kwargs(mode="query"))


def test_validate_response_forbids_extras():
    with pytest.raises(ValidationError):
        ValidateReportFieldsResponse(**_validate_kwargs(sneaky=True))


# ---------- Discriminated union ----------------------------------------------


def test_union_dispatches_on_mode_query():
    adapter = TypeAdapter(ReportFieldsResponse)
    obj = adapter.validate_python(_query_kwargs())
    assert isinstance(obj, QueryReportFieldsResponse)


def test_union_dispatches_on_mode_validate():
    adapter = TypeAdapter(ReportFieldsResponse)
    obj = adapter.validate_python(_validate_kwargs())
    assert isinstance(obj, ValidateReportFieldsResponse)


def test_union_rejects_unknown_mode():
    adapter = TypeAdapter(ReportFieldsResponse)
    with pytest.raises(ValidationError):
        adapter.validate_python({**_query_kwargs(), "mode": "mystery"})
