"""Spec-contract integration test for the Accept resolver.

Loads the shipped ``dist/openapi/resources/SponsoredProducts.json`` (the only
runtime spec source per the commit policy — `.build/` and `openapi/resources/`
are private) and exercises the resolver against a real :class:`MediaTypeRegistry`
to assert each multi-version operation resolves to its expected version.

These predictions catch:

* "Highest declared version" picker regressions (the headline fix).
* Future Amazon spec changes that introduce a v6 — the test should auto-update
  expectations on regen, surfacing version moves loudly.
* Spec-extraction changes in ``build_media_maps_from_spec`` (e.g. dropping
  the lexical sort) that would break order-independent guarantees.
* The moment Amazon ships a multi-base accepts list — the mixed-base guard
  iterates every operation and asserts the resolver doesn't crash.

This is the ONLY test allowed to instantiate ``MediaTypeRegistry`` for resolver
purposes (per the source-agnosticism guarantee in the roadmap doc). Pure-function
unit tests in ``test_accept_resolver.py`` inject ``spec_accepts`` directly.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from amazon_ads_mcp.utils.media import MediaTypeRegistry
from amazon_ads_mcp.utils.media.accept_resolver import (
    parse_vendored_json,
    pick_highest_vendored_json,
    resolve_accept,
)

# Path policy: tests reference dist/openapi/resources/, never .build/ or
# openapi/resources/. dist/ is the only OpenAPI asset tree that ships.
_REPO_ROOT = Path(__file__).resolve().parents[2]
_DIST_RESOURCES = _REPO_ROOT / "dist" / "openapi" / "resources"
_SP_SPEC_PATH = _DIST_RESOURCES / "SponsoredProducts.json"
_DSP_CONVERSIONS_PATH = _DIST_RESOURCES / "AmazonDSPConversions.json"
_DSP_MEASUREMENT_PATH = _DIST_RESOURCES / "AmazonDSPMeasurement.json"
_BRANDMETRICS_PATH = _DIST_RESOURCES / "BrandMetrics.json"
_REPORTING_V3_PATH = _DIST_RESOURCES / "ReportingVersion3.json"


def _load_spec(path: Path) -> dict:
    if not path.exists():
        pytest.skip(f"Spec not found at {path}; build the dist/ tree first.")
    with open(path) as f:
        return json.load(f)


def _load_registry(path: Path) -> MediaTypeRegistry:
    spec = _load_spec(path)
    reg = MediaTypeRegistry()
    reg.add_from_spec(spec)
    return reg


@pytest.fixture(scope="module")
def sp_registry() -> MediaTypeRegistry:
    return _load_registry(_SP_SPEC_PATH)


@pytest.fixture(scope="module")
def sp_spec() -> dict:
    return _load_spec(_SP_SPEC_PATH)


@pytest.fixture(scope="module")
def dsp_conversions_registry() -> MediaTypeRegistry:
    return _load_registry(_DSP_CONVERSIONS_PATH)


@pytest.fixture(scope="module")
def dsp_conversions_spec() -> dict:
    return _load_spec(_DSP_CONVERSIONS_PATH)


@pytest.fixture(scope="module")
def dsp_measurement_registry() -> MediaTypeRegistry:
    return _load_registry(_DSP_MEASUREMENT_PATH)


@pytest.fixture(scope="module")
def dsp_measurement_spec() -> dict:
    return _load_spec(_DSP_MEASUREMENT_PATH)


@pytest.fixture(scope="module")
def brandmetrics_registry() -> MediaTypeRegistry:
    return _load_registry(_BRANDMETRICS_PATH)


@pytest.fixture(scope="module")
def brandmetrics_spec() -> dict:
    return _load_spec(_BRANDMETRICS_PATH)


@pytest.fixture(scope="module")
def reporting_v3_registry() -> MediaTypeRegistry:
    return _load_registry(_REPORTING_V3_PATH)


@pytest.fixture(scope="module")
def reporting_v3_spec() -> dict:
    return _load_spec(_REPORTING_V3_PATH)


# ---------------------------------------------------------------------------
# Headline regression fixes — multi-version operations
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "method,path,expected_accept",
    [
        # The headline fix: was v3 (500), should be v5
        (
            "POST",
            "/sp/targets/keywords/recommendations",
            "application/vnd.spkeywordsrecommendation.v5+json",
        ),
        # Theme-based bid recommendation — same shape, different op
        (
            "POST",
            "/sp/targets/bid/recommendations",
            "application/vnd.spthemebasedbidrecommendation.v5+json",
        ),
        # Targetable categories — GET, multi-version
        (
            "GET",
            "/sp/targets/categories",
            "application/vnd.spproducttargetingresponse.v5+json",
        ),
        # Category recommendations for ASINs — POST, multi-version
        (
            "POST",
            "/sp/targets/categories/recommendations",
            "application/vnd.spproducttargetingresponse.v5+json",
        ),
        # Refinements — only v3/v4 declared, picker returns v4
        (
            "GET",
            "/sp/targets/category/{categoryId}/refinements",
            "application/vnd.spproducttargetingresponse.v4+json",
        ),
        # Optimization rules — v1/v2, picker returns v2
        (
            "POST",
            "/sp/rules/optimization",
            "application/vnd.spoptimizationrules.v2+json",
        ),
        (
            "PUT",
            "/sp/rules/optimization",
            "application/vnd.spoptimizationrules.v2+json",
        ),
        (
            "POST",
            "/sp/rules/optimization/search",
            "application/vnd.spoptimizationrules.v2+json",
        ),
        # Target promotion groups — v1/v2, picker returns v2
        (
            "POST",
            "/sp/targetPromotionGroups",
            "application/vnd.sptargetpromotiongroup.v2+json",
        ),
        (
            "POST",
            "/sp/targetPromotionGroups/list",
            "application/vnd.sptargetpromotiongroup.v2+json",
        ),
        (
            "POST",
            "/sp/targetPromotionGroups/targets",
            "application/vnd.sptargetpromotiongrouptarget.v2+json",
        ),
        (
            "POST",
            "/sp/targetPromotionGroups/targets/list",
            "application/vnd.sptargetpromotiongrouptarget.v2+json",
        ),
    ],
)
def test_multi_version_operations_resolve_to_highest(
    sp_registry: MediaTypeRegistry,
    method: str,
    path: str,
    expected_accept: str,
) -> None:
    """Each multi-version op must resolve to its highest declared vN+json."""
    url = f"https://advertising-api.amazon.com{path}"
    _, accepts = sp_registry.resolve(method, url)
    assert accepts is not None, f"registry has no accepts for {method} {path}"

    resolved = resolve_accept(spec_accepts=accepts, existing="*/*")
    assert resolved == expected_accept, (
        f"{method} {path}: resolved {resolved!r}, expected {expected_accept!r}\n"
        f"  spec accepts: {accepts}"
    )


# ---------------------------------------------------------------------------
# PR #68 contract — single-version SP v3 entity CRUD must keep resolving to v3
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "method,path,expected_accept",
    [
        # SP v3 campaigns (only v3 declared — highest is v3)
        (
            "POST",
            "/sp/campaigns/list",
            "application/vnd.spCampaign.v3+json",
        ),
        # SP v3 ad groups
        (
            "POST",
            "/sp/adGroups/list",
            "application/vnd.spAdGroup.v3+json",
        ),
        # SP v3 keywords
        (
            "POST",
            "/sp/keywords/list",
            "application/vnd.spKeyword.v3+json",
        ),
        # SP v3 product ads
        (
            "POST",
            "/sp/productAds/list",
            "application/vnd.spProductAd.v3+json",
        ),
    ],
)
def test_pr68_single_version_endpoints_unchanged(
    sp_registry: MediaTypeRegistry,
    method: str,
    path: str,
    expected_accept: str,
) -> None:
    """PR #68's wire contract: single-version SP v3 endpoints continue to
    resolve to the v3 vendored type. Validates that "highest" is correct
    when only one version is declared."""
    url = f"https://advertising-api.amazon.com{path}"
    _, accepts = sp_registry.resolve(method, url)
    assert accepts is not None
    resolved = resolve_accept(spec_accepts=accepts, existing="*/*")
    assert resolved == expected_accept


# ---------------------------------------------------------------------------
# Generalized spec-walk crash test — runs across every supported spec
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "spec_fixture_name",
    [
        "sp_spec",
        "dsp_conversions_spec",
        "dsp_measurement_spec",
        "brandmetrics_spec",
        "reporting_v3_spec",
    ],
)
def test_no_operation_in_spec_crashes_resolver(
    spec_fixture_name: str, request: pytest.FixtureRequest
) -> None:
    """Walk every operation in the named spec and confirm the resolver
    returns SOMETHING (a string or None) — never crashes. Catches:
    malformed accepts lists, mixed-base ops we don't know about yet,
    parser regressions on real-world content types. Runs across every
    spec we explicitly support, so future Amazon spec changes that
    introduce a new mixed-base shape get surfaced loudly.
    """
    spec = request.getfixturevalue(spec_fixture_name)
    for path, ops in (spec.get("paths") or {}).items():
        if not isinstance(ops, dict):
            continue
        for method, op in ops.items():
            if not isinstance(op, dict):
                continue
            cts = set()
            for _, resp in (op.get("responses") or {}).items():
                if isinstance(resp, dict):
                    cts.update((resp.get("content") or {}).keys())
            if not cts:
                continue
            accepts = sorted(cts)
            for existing in (None, "*/*", "application/json"):
                result = resolve_accept(spec_accepts=accepts, existing=existing)
                assert result is None or isinstance(result, str), (
                    f"{spec_fixture_name} {method.upper()} {path} "
                    f"existing={existing!r}: got {type(result).__name__}"
                )


def test_mixed_base_operations_fall_back_to_first_listed(sp_spec: dict) -> None:
    """Find every operation in the SP spec whose accepts list contains more
    than one distinct base. Today: at least the
    `spproductrecommendationresponse.asins` / `…themes` op exists. Assert
    the picker abstains and rule 4 returns first-listed (after registry's
    lexical sort). Catches: future regressions where someone implements
    "highest per base" and breaks this contract.
    """
    found_any = False
    for path, ops in (sp_spec.get("paths") or {}).items():
        if not isinstance(ops, dict):
            continue
        for method, op in ops.items():
            if not isinstance(op, dict):
                continue
            cts = set()
            for _, resp in (op.get("responses") or {}).items():
                if isinstance(resp, dict):
                    cts.update((resp.get("content") or {}).keys())
            accepts = sorted(cts)

            bases = set()
            for ct in accepts:
                p = parse_vendored_json(ct)
                if p is not None:
                    bases.add(p[0])
            if len(bases) <= 1:
                continue

            found_any = True
            assert pick_highest_vendored_json(accepts) is None, (
                f"{method.upper()} {path}: picker should abstain on "
                f"{len(bases)} bases ({bases}), but returned a value"
            )
            resolved = resolve_accept(spec_accepts=accepts, existing="*/*")
            assert resolved == accepts[0], (
                f"{method.upper()} {path}: expected first-listed "
                f"{accepts[0]!r}, got {resolved!r}"
            )

    assert found_any, (
        "expected at least one mixed-base operation in current SP spec "
        "(e.g. spproductrecommendationresponse.asins/themes); spec may have "
        "changed shape — re-verify before relaxing this assertion"
    )


# ---------------------------------------------------------------------------
# AmazonDSPConversions — 2 multi-version + 1 mixed-base
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "method,path,expected_accept",
    [
        # dspAmazonListConversionDefinitions: v1 + v2 declared, picker -> v2
        (
            "POST",
            "/accounts/{accountId}/dsp/conversionDefinitions/list",
            "application/vnd.dspconversiondefinition.v2+json",
        ),
        # dspAmazonGetAssociatedConversionDefinitionsForOrder: v1 + v2 declared, picker -> v2
        (
            "GET",
            "/accounts/{accountId}/dsp/orders/{orderId}/conversionDefinitionAssociations",
            "application/vnd.dsporderconversionassociation.v2+json",
        ),
    ],
)
def test_dsp_conversions_multi_version_resolves_to_highest(
    dsp_conversions_registry: MediaTypeRegistry,
    method: str,
    path: str,
    expected_accept: str,
) -> None:
    """DSP Conversions has 2 single-base ops declaring v1 and v2. Resolver
    must pick v2. Same regression class as SP keywords v3->v5; without this
    test, a DSP regression would ship silently."""
    url = f"https://advertising-api.amazon.com{path}"
    _, accepts = dsp_conversions_registry.resolve(method, url)
    assert accepts is not None, f"registry has no accepts for {method} {path}"
    resolved = resolve_accept(spec_accepts=accepts, existing="*/*")
    assert resolved == expected_accept, (
        f"{method} {path}: resolved {resolved!r}, expected {expected_accept!r}\n"
        f"  spec accepts: {accepts}"
    )


def test_dsp_conversions_mixed_base_falls_back_to_first_listed(
    dsp_conversions_registry: MediaTypeRegistry,
) -> None:
    """`dspAmazonGetAssociatedMobileAppForConversionDefinition` declares
    two distinct vendored bases (`dspconversionadtageventassociation` and
    `dspassociatedmobilemeasurementpartnerappregistration`). Picker abstains;
    rule 4 returns lexical-first."""
    _, accepts = dsp_conversions_registry.resolve(
        "GET",
        "https://advertising-api.amazon.com/accounts/123/dsp/conversionDefinitions/456/mobileMeasurementPartnerAppRegistration",
    )
    assert accepts is not None
    assert pick_highest_vendored_json(accepts) is None, (
        f"picker should abstain on mixed bases, got {pick_highest_vendored_json(accepts)!r}"
    )
    resolved = resolve_accept(spec_accepts=accepts, existing="*/*")
    assert resolved == accepts[0], (
        f"expected first-listed {accepts[0]!r}, got {resolved!r}"
    )


# ---------------------------------------------------------------------------
# AmazonDSPMeasurement — 20 multi-version single-base ops
# ---------------------------------------------------------------------------
#
# Test rows below are derived from dist/openapi/resources/AmazonDSPMeasurement.json
# via the helper script `scripts/dump_multi_version_ops.py`. Re-run that script
# after spec regeneration to refresh the expected values; commit any changes.


@pytest.mark.parametrize(
    "method,path,expected_accept",
    [
        # CheckDSPBrandLiftEligibility: v1, v1.1
        (
            "POST",
            "/dsp/measurement/eligibility/brandLift",
            "application/vnd.measurementeligibility.v1.1+json",
        ),
        # CheckDSPOmnichannelMetricsEligibility: v1.2, v1.3
        (
            "POST",
            "/dsp/measurement/eligibility/omnichannelMetrics",
            "application/vnd.measurementeligibility.v1.3+json",
        ),
        # GetDSPBrandLiftStudies: v1, v1.1, v1.2, v1.3
        (
            "GET",
            "/dsp/measurement/studies/brandLift",
            "application/vnd.studymanagement.v1.3+json",
        ),
        # CreateDSPBrandLiftStudies: v1, v1.1, v1.2, v1.3
        (
            "POST",
            "/dsp/measurement/studies/brandLift",
            "application/vnd.studymanagement.v1.3+json",
        ),
        # UpdateDSPBrandLiftStudies: v1, v1.1, v1.2, v1.3
        (
            "PUT",
            "/dsp/measurement/studies/brandLift",
            "application/vnd.studymanagement.v1.3+json",
        ),
        # GetDSPOmnichannelMetricsStudies: v1.2, v1.3
        (
            "GET",
            "/dsp/measurement/studies/omnichannelMetrics",
            "application/vnd.studymanagement.v1.3+json",
        ),
        # CreateDSPOmnichannelMetricsStudies: v1.2, v1.3
        (
            "POST",
            "/dsp/measurement/studies/omnichannelMetrics",
            "application/vnd.studymanagement.v1.3+json",
        ),
        # UpdateDSPOmnichannelMetricsStudies: v1.2, v1.3
        (
            "PUT",
            "/dsp/measurement/studies/omnichannelMetrics",
            "application/vnd.studymanagement.v1.3+json",
        ),
        # GetDSPOmnichannelMetricsStudyResult: v1.2, v1.3
        (
            "GET",
            "/dsp/measurement/studies/omnichannelMetrics/{studyId}/result",
            "application/vnd.measurementresult.v1.3+json",
        ),
        # CheckPlanningEligibility: v1.1, v1.3
        (
            "POST",
            "/measurement/planning/eligibility",
            "application/vnd.measurementeligibility.v1.3+json",
        ),
        # CancelMeasurementStudies: v1, v1.1, v1.2, v1.3
        (
            "DELETE",
            "/measurement/studies",
            "application/vnd.studymanagement.v1.3+json",
        ),
        # GetStudies: v1, v1.1, v1.2, v1.3
        (
            "GET",
            "/measurement/studies",
            "application/vnd.studymanagement.v1.3+json",
        ),
        # GetDSPBrandLiftStudyResult: v1, v1.1
        (
            "GET",
            "/measurement/studies/brandLift/{studyId}/result",
            "application/vnd.measurementresult.v1.1+json",
        ),
        # GetSurveys: v1, v1.1, v1.2, v1.3
        (
            "GET",
            "/measurement/studies/surveys",
            "application/vnd.studymanagement.v1.3+json",
        ),
        # CreateSurveys: v1, v1.1, v1.2, v1.3
        (
            "POST",
            "/measurement/studies/surveys",
            "application/vnd.studymanagement.v1.3+json",
        ),
        # UpdateSurveys: v1, v1.1, v1.2, v1.3
        (
            "PUT",
            "/measurement/studies/surveys",
            "application/vnd.studymanagement.v1.3+json",
        ),
        # vendorProduct: v1, v1.1
        (
            "POST",
            "/measurement/vendorProducts/list",
            "application/vnd.measurementvendor.v1.1+json",
        ),
        # omnichannelMetricsBrandSearch: v1.2, v1.3
        (
            "POST",
            "/measurement/vendorProducts/omnichannelMetrics/brands/list",
            "application/vnd.ocmbrands.v1.3+json",
        ),
        # vendorProductPolicy: v1, v1.1
        (
            "GET",
            "/measurement/vendorProducts/policies",
            "application/vnd.measurementvendor.v1.1+json",
        ),
        # vendorProductSurveyQuestionTemplates: v1, v1.1
        (
            "GET",
            "/measurement/vendorProducts/surveyQuestionTemplates",
            "application/vnd.measurementvendor.v1.1+json",
        ),
    ],
)
def test_dsp_measurement_multi_version_resolves_to_highest(
    dsp_measurement_registry: MediaTypeRegistry,
    method: str,
    path: str,
    expected_accept: str,
) -> None:
    """All 20 DSP Measurement multi-version ops must resolve to highest
    declared (major, minor). Locks the wire contract for measurement
    eligibility, study management, study results, survey management, and
    vendor product endpoints. Registry returns lexically-sorted accepts;
    picker reorders by parsed (major, minor)."""
    url = f"https://advertising-api.amazon.com{path}"
    _, accepts = dsp_measurement_registry.resolve(method, url)
    assert accepts is not None, f"registry has no accepts for {method} {path}"
    resolved = resolve_accept(spec_accepts=accepts, existing="*/*")
    assert resolved == expected_accept, (
        f"{method} {path}: resolved {resolved!r}, expected {expected_accept!r}\n"
        f"  spec accepts: {accepts}"
    )


# ---------------------------------------------------------------------------
# BrandMetrics — 2 mixed-base multi-version ops (documented contract)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "method,path",
    [
        ("POST", "/insights/brandMetrics/report"),
        ("GET", "/insights/brandMetrics/report/{reportId}"),
    ],
)
def test_brandmetrics_mixed_base_returns_first_listed(
    brandmetrics_registry: MediaTypeRegistry,
    method: str,
    path: str,
) -> None:
    """Both BrandMetrics ops declare insightsbrandmetrics (v1, v1.1) AND
    insightsbrandmetricserror (v1) in one accepts list. Picker abstains
    on mixed bases (`insightsbrandmetrics` vs `insightsbrandmetricserror`);
    rule 4 returns lexical-first.

    Lexical sort places `insightsbrandmetrics.v1+json` before
    `insightsbrandmetrics.v1.1+json` (because '+' (0x2B) < '.' (0x2E)),
    and both before `insightsbrandmetricserror.*` (because `.` (0x2E) <
    `e` (0x65)).

    This is the current contract per the design discipline: callers
    needing v1.1 specifically must pin Accept at the call site (preserved
    by resolver rule 1). Rejected alternatives: bucket-by-base, special-case
    "error" base names — both violate spec-driven design.
    """
    url = f"https://advertising-api.amazon.com{path}"
    _, accepts = brandmetrics_registry.resolve(method, url)
    assert accepts is not None
    assert pick_highest_vendored_json(accepts) is None, (
        f"picker should abstain on mixed bases, got "
        f"{pick_highest_vendored_json(accepts)!r}"
    )
    resolved = resolve_accept(spec_accepts=accepts, existing="*/*")
    assert resolved == "application/vnd.insightsbrandmetrics.v1+json", (
        f"expected lexical-first 'insightsbrandmetrics.v1+json', got {resolved!r}\n"
        f"  spec accepts: {accepts}"
    )


# ---------------------------------------------------------------------------
# ReportingVersion3 — 0 multi-version ops; minimal sanity scan
# ---------------------------------------------------------------------------


def test_reporting_v3_single_version_ops_resolve_to_declared(
    reporting_v3_spec: dict,
    reporting_v3_registry: MediaTypeRegistry,
) -> None:
    """ReportingVersion3 declares one version per operation. Walk every
    op; for each that has any vendored type declared, assert the resolver
    returns a value that is in the declared set (i.e. doesn't invent or
    drop content types). One assertion across the whole spec rather than
    per-op rows — avoids verifying identity behavior 30 times for
    single-version specs.
    """
    checked = 0
    for path, ops in (reporting_v3_spec.get("paths") or {}).items():
        if not isinstance(ops, dict):
            continue
        for method, op in ops.items():
            if not isinstance(op, dict):
                continue
            url = f"https://advertising-api.amazon.com{path}"
            _, accepts = reporting_v3_registry.resolve(method, url)
            if not accepts:
                continue
            resolved = resolve_accept(spec_accepts=accepts, existing="*/*")
            assert resolved in accepts, (
                f"{method.upper()} {path}: resolved {resolved!r} not in "
                f"declared accepts {accepts}"
            )
            checked += 1
    assert checked > 0, (
        "ReportingVersion3 should have at least one operation with a "
        "vendored content type — fixture may be empty or spec changed shape"
    )
