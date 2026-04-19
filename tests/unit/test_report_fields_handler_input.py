"""Input-validation tests for the report_fields handler.

Locked contract (adsv1.md §4.3, §4.4, §4.10):
- Input model extra="forbid"
- Cross-mode arg contamination → INVALID_MODE_ARGS
- mode="query" with no query-mode args → INVALID_MODE_ARGS
- Oversized list/string inputs → INVALID_INPUT_SIZE
- limit > 100 rejected at Pydantic layer (schema constraint, not sanitation)
- validate mode scope: only allv1_AdsApiv1CreateReport → UNSUPPORTED_OPERATION for others
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from amazon_ads_mcp.tools.report_fields_errors import ReportFieldsErrorCode
from amazon_ads_mcp.tools.report_fields_v1_handler import (
    ReportFieldsInput,
    ReportFieldsToolError,
    handle,
)


# ---------- ReportFieldsInput schema constraints ---------------------------


def test_input_forbids_extras():
    with pytest.raises(ValidationError):
        ReportFieldsInput(mode="query", search="x", sneaky="dropped")


def test_input_limit_max_100_rejected_at_pydantic():
    """limit > 100 raises ValidationError (schema constraint), NOT
    ReportFieldsToolError(INVALID_INPUT_SIZE)."""
    with pytest.raises(ValidationError):
        ReportFieldsInput(mode="query", search="x", limit=101)


def test_input_limit_negative_rejected_at_pydantic():
    with pytest.raises(ValidationError):
        ReportFieldsInput(mode="query", search="x", limit=-1)


def test_input_offset_negative_rejected_at_pydantic():
    with pytest.raises(ValidationError):
        ReportFieldsInput(mode="query", search="x", offset=-1)


# ---------- Cross-mode arg contamination ----------------------------------


def test_query_mode_with_validate_fields_fails():
    with pytest.raises(ReportFieldsToolError) as excinfo:
        handle(mode="query", search="x", validate_fields=["a"])
    assert excinfo.value.code == ReportFieldsErrorCode.INVALID_MODE_ARGS


def test_validate_mode_with_query_arg_fails():
    with pytest.raises(ReportFieldsToolError) as excinfo:
        handle(mode="validate", validate_fields=["metric.clicks"], search="x")
    assert excinfo.value.code == ReportFieldsErrorCode.INVALID_MODE_ARGS


def test_validate_mode_with_category_fails():
    with pytest.raises(ReportFieldsToolError) as excinfo:
        handle(mode="validate", validate_fields=["metric.clicks"], category="metric")
    assert excinfo.value.code == ReportFieldsErrorCode.INVALID_MODE_ARGS


def test_validate_mode_without_validate_fields_fails():
    """validate mode must be told what to validate."""
    with pytest.raises(ReportFieldsToolError) as excinfo:
        handle(mode="validate")
    assert excinfo.value.code == ReportFieldsErrorCode.INVALID_MODE_ARGS


def test_query_mode_with_no_args_fails():
    """Prevents accidental full-catalog dump."""
    with pytest.raises(ReportFieldsToolError) as excinfo:
        handle(mode="query")
    assert excinfo.value.code == ReportFieldsErrorCode.INVALID_MODE_ARGS


# ---------- Input sanitation caps (§4.10) ---------------------------------


def test_fields_list_over_cap_rejected():
    with pytest.raises(ReportFieldsToolError) as excinfo:
        handle(mode="query", fields=[f"metric.x{i}" for i in range(201)])
    assert excinfo.value.code == ReportFieldsErrorCode.INVALID_INPUT_SIZE


def test_validate_fields_list_over_cap_rejected():
    with pytest.raises(ReportFieldsToolError) as excinfo:
        handle(mode="validate", validate_fields=[f"metric.x{i}" for i in range(201)])
    assert excinfo.value.code == ReportFieldsErrorCode.INVALID_INPUT_SIZE


def test_compatible_with_list_over_cap_rejected():
    with pytest.raises(ReportFieldsToolError) as excinfo:
        handle(mode="query", compatible_with=[f"x{i}" for i in range(51)])
    assert excinfo.value.code == ReportFieldsErrorCode.INVALID_INPUT_SIZE


def test_requires_list_over_cap_rejected():
    with pytest.raises(ReportFieldsToolError) as excinfo:
        handle(mode="query", requires=[f"x{i}" for i in range(51)])
    assert excinfo.value.code == ReportFieldsErrorCode.INVALID_INPUT_SIZE


def test_search_string_over_cap_rejected():
    with pytest.raises(ReportFieldsToolError) as excinfo:
        handle(mode="query", search="x" * 201)
    assert excinfo.value.code == ReportFieldsErrorCode.INVALID_INPUT_SIZE


# ---------- Validate scope (§4.4) -----------------------------------------


def test_validate_for_non_v1_operation_fails():
    for op in ("rp_createAsyncReport", "br_generateBrandMetricsReport", "mmm_createMmmReport"):
        with pytest.raises(ReportFieldsToolError) as excinfo:
            handle(mode="validate", operation=op, validate_fields=["metric.clicks"])
        assert excinfo.value.code == ReportFieldsErrorCode.UNSUPPORTED_OPERATION


def test_validate_for_unknown_operation_fails():
    with pytest.raises(ReportFieldsToolError) as excinfo:
        handle(mode="validate", operation="does_not_exist", validate_fields=["metric.clicks"])
    assert excinfo.value.code == ReportFieldsErrorCode.UNSUPPORTED_OPERATION


def test_validate_accepts_canonical_v1_operation_alias():
    """AdsApiv1CreateReport alias resolves to the canonical v1 op."""
    # Should not raise (validate_fields is trivially valid).
    handle(mode="validate", operation="AdsApiv1CreateReport", validate_fields=["metric.clicks"])
