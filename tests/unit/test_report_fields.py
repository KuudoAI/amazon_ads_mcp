"""Unit tests for report field catalog helpers."""

from amazon_ads_mcp.tools import report_fields


def test_get_report_fields_catalog_lists_operations():
    result = report_fields.get_report_fields_catalog()
    assert result["success"] is True
    assert "allv1_AdsApiv1CreateReport" in result["operations"]
    assert "rp_createAsyncReport" in result["operations"]
    assert "br_generateBrandMetricsReport" in result["operations"]
    assert "mmm_createMmmReport" in result["operations"]


def test_get_report_fields_catalog_by_alias():
    result = report_fields.get_report_fields_catalog("AdsApiv1CreateReport")
    assert result["success"] is True
    assert result["operation"] == "allv1_AdsApiv1CreateReport"
    assert "field_groups" in result["catalog_entry"]


def test_get_report_fields_catalog_unknown_operation():
    result = report_fields.get_report_fields_catalog("does_not_exist")
    assert result["success"] is False
    assert result["error"] == "Unknown operation"


def test_get_report_fields_catalog_aliases_for_other_report_apis():
    rp_result = report_fields.get_report_fields_catalog("ReportingVersion3_createAsyncReport")
    assert rp_result["success"] is True
    assert rp_result["operation"] == "rp_createAsyncReport"

    br_result = report_fields.get_report_fields_catalog("generateBrandMetricsReport")
    assert br_result["success"] is True
    assert br_result["operation"] == "br_generateBrandMetricsReport"

    mmm_result = report_fields.get_report_fields_catalog("createMmmReport")
    assert mmm_result["success"] is True
    assert mmm_result["operation"] == "mmm_createMmmReport"
