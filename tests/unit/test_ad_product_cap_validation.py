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
    "ad_product,cap",
    [
        # Wire-trace confirmed caps from client R2 follow-up report
        ("SPONSORED_BRANDS", 100),
        ("SPONSORED_DISPLAY", 1000),
        ("SPONSORED_TELEVISION", 1000),
    ],
)
def test_other_ad_product_caps_enforced_at_boundary(ad_product, cap):
    """SB / SD / TV caps now confirmed via wire trace. Validate at the
    boundary (cap value passes; cap+1 raises)."""
    # At-cap passes
    check_ad_product_caps(
        "QueryCampaign",
        {
            "adProductFilter": {"include": [ad_product]},
            "maxResults": cap,
        },
    )
    # Below cap passes
    check_ad_product_caps(
        "QueryCampaign",
        {
            "adProductFilter": {"include": [ad_product]},
            "maxResults": max(1, cap // 2),
        },
    )
    # Over-cap raises with cap value + ad product in message
    with pytest.raises(ValidationError) as excinfo:
        check_ad_product_caps(
            "QueryCampaign",
            {
                "adProductFilter": {"include": [ad_product]},
                "maxResults": cap + 1,
            },
        )
    msg = str(excinfo.value)
    assert ad_product in msg
    assert str(cap) in msg
    assert str(cap + 1) in msg


def test_sponsored_brands_50x_overshoot_caught():
    """The most severe mismatch: schema declares max=5000 but real cap
    is 100 (50x). Most likely to surprise SB users. Locked at this
    extreme to make the regression visible if SB's cap changes."""
    with pytest.raises(ValidationError) as excinfo:
        check_ad_product_caps(
            "QueryCampaign",
            {
                "adProductFilter": {"include": ["SPONSORED_BRANDS"]},
                "maxResults": 5000,  # the schema max
            },
        )
    msg = str(excinfo.value)
    assert "SPONSORED_BRANDS" in msg
    assert "100" in msg
    assert "5000" in msg


def test_amazon_dsp_still_fails_open():
    """AMAZON_DSP cap remains unknown (different error path; needs
    DSP-eligible profile to characterize). Fail-open contract preserved
    for unconfirmed-cap ad products: schema's max=5000 applies via R1."""
    check_ad_product_caps(
        "QueryCampaign",
        {
            "adProductFilter": {"include": ["AMAZON_DSP"]},
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
