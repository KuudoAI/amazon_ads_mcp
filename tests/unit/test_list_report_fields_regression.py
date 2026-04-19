"""Regression fence for list_report_fields (adsv1.md §E.1 lock).

These deep-equality snapshots lock the current response shape + values so
any Phase E/F change that silently mutates `list_report_fields` output
fails loudly. The fence covers:

- no-arg response (operations listing + full catalog)
- allv1_AdsApiv1CreateReport → minimal baseline (NOT the 800+ entry
  packaged catalog)
- rp_createAsyncReport, br_generateBrandMetricsReport, mmm_createMmmReport
  → existing schema-derived entries unchanged

Use deep-equality (parsed JSON), not byte-for-byte — permits formatting
changes from dependency upgrades without noisy failures (§5 AC).
"""

from __future__ import annotations

from amazon_ads_mcp.tools import report_fields


# ---------- expected snapshots -----------------------------------------------


_V1_ENTRY = {
    "description": "Ads API v1 asynchronous report creation field catalog",
    "field_groups": {
        "dimensions": [
            "campaign.id",
            "campaign.name",
            "adGroup.id",
            "adGroup.name",
            "searchTerm.value",
        ],
        "filters": ["adProduct.value"],
        "metrics": [
            "metric.impressions",
            "metric.clicks",
            "metric.sales",
            "metric.purchases",
        ],
        "required_supporting_fields": ["budgetCurrency.value"],
        "time_dimensions": ["date.value"],
    },
    "notes": [
        "Use advertiser account IDs (amzn1.ads-account.g.*), not numeric profile IDs.",
        "Start with this minimal field set, then add fields incrementally.",
        "Unsupported fields usually return HTTP 400 with unknown field errors.",
    ],
    "status": "empirically-validated-minimal",
}

_RP_ENTRY = {
    "description": "Reporting v3 async report request schema guide",
    "notes": [
        "Columns and groupBy values are reportTypeId-dependent.",
        "Use conservative iterative expansion when adding columns/filters.",
    ],
    "request_schema": {
        "configuration_enums": {
            "adProduct": [
                "ALL",
                "DEMAND_SIDE_PLATFORM",
                "SPONSORED_BRANDS",
                "SPONSORED_DISPLAY",
                "SPONSORED_PRODUCTS",
                "SPONSORED_TELEVISION",
            ],
            "format": ["GZIP_JSON"],
            "timeUnit": ["DAILY", "SUMMARY"],
        },
        "filter_shape": {"item_fields": ["field", "values[]"]},
        "required_configuration_fields": [
            "adProduct",
            "reportTypeId",
            "columns",
            "groupBy",
            "format",
            "timeUnit",
        ],
        "required_root_fields": ["configuration", "startDate", "endDate"],
    },
    "status": "schema-derived",
}

_BR_ENTRY = {
    "description": "Brand Metrics report request schema guide",
    "notes": [
        "metrics is optional; omitting it returns all available metrics.",
        "Date range max is 3 months per schema description.",
    ],
    "request_schema": {
        "enums": {
            "format": ["CSV", "JSON"],
            "lookBackPeriod": ["1W", "1M", "1CM", "1w", "1m", "1cm"],
        },
        "optional_fields": [
            "brandName",
            "categoryPath[]",
            "categoryTreeName",
            "lookBackPeriod",
            "metrics[]",
            "reportStartDate",
            "reportEndDate",
        ],
    },
    "status": "schema-derived",
}

_MMM_ENTRY = {
    "description": "Marketing Mix Modeling report request schema guide",
    "notes": [
        "brandGroupId comes from mmm_listMmmBrandGroups.",
        "For WEEKLY timeUnit, start/end day constraints apply (see schema).",
    ],
    "request_schema": {
        "configuration_enums": {
            "geoDimension": ["COUNTRY", "POSTAL_CODE", "DMA"],
            "metricsType": ["MEDIA_ONLY", "MEDIA_AND_SALES"],
            "timeUnit": ["DAILY", "WEEKLY"],
        },
        "required_configuration_fields": [
            "brandGroupId",
            "geoDimension",
            "metricsType",
            "timeUnit",
        ],
    },
    "status": "schema-derived",
}


# ---------- tests ------------------------------------------------------------


def test_no_arg_response_shape_and_values_unchanged():
    result = report_fields.get_report_fields_catalog()
    assert result == {
        "success": True,
        "operations": [
            "allv1_AdsApiv1CreateReport",
            "br_generateBrandMetricsReport",
            "mmm_createMmmReport",
            "rp_createAsyncReport",
        ],
        "catalog": {
            "allv1_AdsApiv1CreateReport": _V1_ENTRY,
            "br_generateBrandMetricsReport": _BR_ENTRY,
            "mmm_createMmmReport": _MMM_ENTRY,
            "rp_createAsyncReport": _RP_ENTRY,
        },
        "message": "Report field catalog by operation",
    }


def test_v1_operation_returns_minimal_baseline_not_full_catalog():
    """Critical: list_report_fields(operation='allv1_...') must return the
    minimal 10-field baseline, NOT the 817-entry packaged catalog."""
    result = report_fields.get_report_fields_catalog("allv1_AdsApiv1CreateReport")
    assert result == {
        "success": True,
        "operation": "allv1_AdsApiv1CreateReport",
        "catalog_entry": _V1_ENTRY,
    }
    # Sanity guard — no drift to the big catalog.
    groups = result["catalog_entry"]["field_groups"]
    total_fields = sum(len(v) for v in groups.values())
    assert total_fields < 20, (
        "list_report_fields must not expand into the packaged 817-record "
        f"catalog (got {total_fields} fields)"
    )


def test_rp_entry_unchanged():
    result = report_fields.get_report_fields_catalog("rp_createAsyncReport")
    assert result == {
        "success": True,
        "operation": "rp_createAsyncReport",
        "catalog_entry": _RP_ENTRY,
    }


def test_br_entry_unchanged():
    result = report_fields.get_report_fields_catalog("br_generateBrandMetricsReport")
    assert result == {
        "success": True,
        "operation": "br_generateBrandMetricsReport",
        "catalog_entry": _BR_ENTRY,
    }


def test_mmm_entry_unchanged():
    result = report_fields.get_report_fields_catalog("mmm_createMmmReport")
    assert result == {
        "success": True,
        "operation": "mmm_createMmmReport",
        "catalog_entry": _MMM_ENTRY,
    }


def test_aliases_still_resolve_to_canonical():
    for alias in ("AdsApiv1CreateReport", "AdsAPIv1Beta_AdsApiv1CreateReport"):
        r = report_fields.get_report_fields_catalog(alias)
        assert r["operation"] == "allv1_AdsApiv1CreateReport"
