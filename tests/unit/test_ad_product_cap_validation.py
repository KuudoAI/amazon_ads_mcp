"""Unit tests for R2 — per-ad-product conditional maxResults cap validator.

Schema declares ``maxResults: maximum: 5000`` on QueryCampaign / QueryTarget
endpoints, but Amazon enforces lower per-ad-product caps. Confirmed via
wire trace: SPONSORED_PRODUCTS = 1000. The other ad products
(SPONSORED_BRANDS, SPONSORED_DISPLAY, SPONSORED_TELEVISION, AMAZON_DSP)
have unknown caps; the validator fails open for them so we don't
manufacture a false positive — the schema's max=5000 still applies.

Default ON via MCP_AD_PRODUCT_CAP_VALIDATION_ENABLED (per repo policy).
Fail-open on missing/malformed adProductFilter so unrelated tools and
edge cases aren't broken.
"""

from __future__ import annotations

import pytest

from amazon_ads_mcp.middleware.schema_normalization import (
    check_ad_product_caps,
)
from amazon_ads_mcp.utils.errors import ErrorCategory, ValidationError


@pytest.fixture(autouse=True)
def _enable_cap_validation(monkeypatch):
    from amazon_ads_mcp.config.settings import Settings
    from amazon_ads_mcp.middleware import schema_normalization as sn_module

    monkeypatch.setattr(sn_module, "settings", Settings())


def test_default_on_without_env(monkeypatch):
    monkeypatch.delenv("MCP_AD_PRODUCT_CAP_VALIDATION_ENABLED", raising=False)
    from amazon_ads_mcp.config.settings import Settings

    fresh = Settings()
    assert fresh.mcp_ad_product_cap_validation_enabled is True


def test_opt_out_disables_validation(monkeypatch):
    monkeypatch.setenv("MCP_AD_PRODUCT_CAP_VALIDATION_ENABLED", "false")
    from amazon_ads_mcp.config.settings import Settings
    from amazon_ads_mcp.middleware import schema_normalization as sn_module

    monkeypatch.setattr(sn_module, "settings", Settings())

    check_ad_product_caps(
        "QueryCampaign",
        {
            "adProductFilter": {"include": ["SPONSORED_PRODUCTS"]},
            "maxResults": 1500,
        },
    )


def test_sponsored_products_at_cap_passes():
    check_ad_product_caps(
        "QueryCampaign",
        {
            "adProductFilter": {"include": ["SPONSORED_PRODUCTS"]},
            "maxResults": 1000,
        },
    )


def test_sponsored_products_below_cap_passes():
    check_ad_product_caps(
        "QueryCampaign",
        {
            "adProductFilter": {"include": ["SPONSORED_PRODUCTS"]},
            "maxResults": 500,
        },
    )


def test_sponsored_products_above_cap_raises():
    with pytest.raises(ValidationError) as excinfo:
        check_ad_product_caps(
            "QueryCampaign",
            {
                "adProductFilter": {"include": ["SPONSORED_PRODUCTS"]},
                "maxResults": 1001,
            },
        )
    err = excinfo.value
    assert err.category == ErrorCategory.VALIDATION
    assert err.details.get("error_code") == "INPUT_VALIDATION_FAILED"
    msg = str(err)
    assert "SPONSORED_PRODUCTS" in msg
    assert "1000" in msg
    assert "1001" in msg


def test_sponsored_products_well_above_cap_raises():
    with pytest.raises(ValidationError):
        check_ad_product_caps(
            "QueryCampaign",
            {
                "adProductFilter": {"include": ["SPONSORED_PRODUCTS"]},
                "maxResults": 5000,
            },
        )


@pytest.mark.parametrize(
    "ad_product",
    [
        "SPONSORED_BRANDS",
        "SPONSORED_DISPLAY",
        "SPONSORED_TELEVISION",
        "AMAZON_DSP",
    ],
)
def test_unknown_ad_product_fails_open(ad_product):
    """Ad products without a confirmed cap pass through. Schema's
    max=5000 still applies via R1's schema-constraint validator."""
    check_ad_product_caps(
        "QueryCampaign",
        {
            "adProductFilter": {"include": [ad_product]},
            "maxResults": 5000,
        },
    )


def test_no_args_no_op():
    check_ad_product_caps("QueryCampaign", None)
    check_ad_product_caps("QueryCampaign", {})


def test_missing_ad_product_filter_no_op():
    check_ad_product_caps(
        "QueryCampaign",
        {"maxResults": 1500},
    )


def test_missing_max_results_no_op():
    check_ad_product_caps(
        "QueryCampaign",
        {"adProductFilter": {"include": ["SPONSORED_PRODUCTS"]}},
    )


def test_malformed_ad_product_filter_no_op():
    check_ad_product_caps(
        "QueryCampaign",
        {
            "adProductFilter": "not_an_object",
            "maxResults": 1500,
        },
    )
    check_ad_product_caps(
        "QueryCampaign",
        {
            "adProductFilter": {"include": "not_a_list"},
            "maxResults": 1500,
        },
    )
    check_ad_product_caps(
        "QueryCampaign",
        {
            "adProductFilter": {"include": []},
            "maxResults": 1500,
        },
    )


def test_max_results_non_integer_no_op():
    check_ad_product_caps(
        "QueryCampaign",
        {
            "adProductFilter": {"include": ["SPONSORED_PRODUCTS"]},
            "maxResults": "not-a-number",
        },
    )


def test_unrelated_tool_no_op():
    check_ad_product_caps(
        "search_profiles",
        {"limit": 200},
    )


def test_unknown_ad_product_value_no_op():
    """Unknown ad-product string (typo or future) → no-op. R1 catches
    the enum violation. This validator only acts when it knows the cap."""
    check_ad_product_caps(
        "QueryCampaign",
        {
            "adProductFilter": {"include": ["NEW_AD_PRODUCT_2030"]},
            "maxResults": 5000,
        },
    )


@pytest.mark.parametrize(
    "tool_name",
    [
        "QueryCampaign",
        "QueryTarget",
        "DSPQueryTarget",
        "SBQueryTarget",
        "SDQueryTarget",
        "allv1_QueryCampaign",
        "allv1_QueryTarget",
    ],
)
def test_cap_enforcement_applies_to_each_known_op(tool_name):
    with pytest.raises(ValidationError):
        check_ad_product_caps(
            tool_name,
            {
                "adProductFilter": {"include": ["SPONSORED_PRODUCTS"]},
                "maxResults": 1001,
            },
        )


def test_error_envelope_includes_actionable_details():
    with pytest.raises(ValidationError) as excinfo:
        check_ad_product_caps(
            "QueryCampaign",
            {
                "adProductFilter": {"include": ["SPONSORED_PRODUCTS"]},
                "maxResults": 1500,
            },
        )
    err = excinfo.value
    assert err.details.get("error_code") == "INPUT_VALIDATION_FAILED"
    violations = err.details.get("violations") or []
    assert violations, f"expected violations list, got {err.details}"
    v = violations[0]
    assert v.get("path") == "maxResults"
    assert "SPONSORED_PRODUCTS" in v.get("issue", "")
    assert "1000" in v.get("issue", "")
    assert "1500" in v.get("issue", "")
