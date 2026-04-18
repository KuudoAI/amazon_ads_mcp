"""Report field catalog helpers.

Provides a stable, operation-scoped field catalog that LLMs can query
instead of guessing report fields from prose descriptions.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

# Canonical key names used by the tool.
ADSAPI_V1_CREATE = "allv1_AdsApiv1CreateReport"
REPORTING_V3_CREATE = "rp_createAsyncReport"
BRAND_METRICS_CREATE = "br_generateBrandMetricsReport"
MMM_CREATE = "mmm_createMmmReport"

# Empirically safe baseline for AdsAPI v1 report queries.
# Keep this conservative; expand only after validation.
_ADSAPI_V1_SAFE_FIELDS: Dict[str, List[str]] = {
    "time_dimensions": [
        "date.value",
    ],
    "dimensions": [
        "campaign.id",
        "campaign.name",
        "adGroup.id",
        "adGroup.name",
        "searchTerm.value",
    ],
    "metrics": [
        "metric.impressions",
        "metric.clicks",
        "metric.sales",
        "metric.purchases",
    ],
    "required_supporting_fields": [
        "budgetCurrency.value",
    ],
    "filters": [
        "adProduct.value",
    ],
}

_CATALOG: Dict[str, Dict[str, Any]] = {
    ADSAPI_V1_CREATE: {
        "description": "Ads API v1 asynchronous report creation field catalog",
        "status": "empirically-validated-minimal",
        "notes": [
            "Use advertiser account IDs (amzn1.ads-account.g.*), not numeric profile IDs.",
            "Start with this minimal field set, then add fields incrementally.",
            "Unsupported fields usually return HTTP 400 with unknown field errors.",
        ],
        "field_groups": _ADSAPI_V1_SAFE_FIELDS,
    },
    REPORTING_V3_CREATE: {
        "description": "Reporting v3 async report request schema guide",
        "status": "schema-derived",
        "notes": [
            "Columns and groupBy values are reportTypeId-dependent.",
            "Use conservative iterative expansion when adding columns/filters.",
        ],
        "request_schema": {
            "required_root_fields": [
                "configuration",
                "startDate",
                "endDate",
            ],
            "required_configuration_fields": [
                "adProduct",
                "reportTypeId",
                "columns",
                "groupBy",
                "format",
                "timeUnit",
            ],
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
            "filter_shape": {
                "item_fields": ["field", "values[]"],
            },
        },
    },
    BRAND_METRICS_CREATE: {
        "description": "Brand Metrics report request schema guide",
        "status": "schema-derived",
        "notes": [
            "metrics is optional; omitting it returns all available metrics.",
            "Date range max is 3 months per schema description.",
        ],
        "request_schema": {
            "optional_fields": [
                "brandName",
                "categoryPath[]",
                "categoryTreeName",
                "lookBackPeriod",
                "metrics[]",
                "reportStartDate",
                "reportEndDate",
            ],
            "enums": {
                "format": ["CSV", "JSON"],
                "lookBackPeriod": ["1W", "1M", "1CM", "1w", "1m", "1cm"],
            },
        },
    },
    MMM_CREATE: {
        "description": "Marketing Mix Modeling report request schema guide",
        "status": "schema-derived",
        "notes": [
            "brandGroupId comes from mmm_listMmmBrandGroups.",
            "For WEEKLY timeUnit, start/end day constraints apply (see schema).",
        ],
        "request_schema": {
            "required_configuration_fields": [
                "brandGroupId",
                "geoDimension",
                "metricsType",
                "timeUnit",
            ],
            "configuration_enums": {
                "geoDimension": ["COUNTRY", "POSTAL_CODE", "DMA"],
                "metricsType": ["MEDIA_ONLY", "MEDIA_AND_SALES"],
                "timeUnit": ["DAILY", "WEEKLY"],
            },
        },
    },
}

_ALIASES = {
    "AdsApiv1CreateReport": ADSAPI_V1_CREATE,
    "allv1_AdsApiv1CreateReport": ADSAPI_V1_CREATE,
    "AdsAPIv1Beta_AdsApiv1CreateReport": ADSAPI_V1_CREATE,
    "createAsyncReport": REPORTING_V3_CREATE,
    "ReportingVersion3_createAsyncReport": REPORTING_V3_CREATE,
    "generateBrandMetricsReport": BRAND_METRICS_CREATE,
    "BrandMetrics_generateBrandMetricsReport": BRAND_METRICS_CREATE,
    "createMmmReport": MMM_CREATE,
    "ReportingMarketingMixModeling_createMmmReport": MMM_CREATE,
}


def list_catalog_operations() -> List[str]:
    """Return known operation keys for report field catalogs."""
    return sorted(_CATALOG.keys())


def resolve_operation_key(operation: Optional[str]) -> Optional[str]:
    """Normalize operation aliases to canonical keys."""
    if not operation:
        return None
    if operation in _CATALOG:
        return operation
    return _ALIASES.get(operation)


def get_report_fields_catalog(operation: Optional[str] = None) -> Dict[str, Any]:
    """Return report field catalog for one operation or all operations."""
    if not operation:
        return {
            "success": True,
            "operations": list_catalog_operations(),
            "catalog": _CATALOG,
            "message": "Report field catalog by operation",
        }

    resolved = resolve_operation_key(operation)
    if not resolved:
        return {
            "success": False,
            "error": "Unknown operation",
            "operation": operation,
            "operations": list_catalog_operations(),
            "hint": "Call without `operation` to list supported operation keys",
        }

    return {
        "success": True,
        "operation": resolved,
        "catalog_entry": _CATALOG[resolved],
    }
