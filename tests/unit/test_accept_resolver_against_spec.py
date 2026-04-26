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
    pick_highest_vendored_json,
    resolve_accept,
)

# Path policy: tests reference dist/openapi/resources/, never .build/ or
# openapi/resources/. dist/ is the only OpenAPI asset tree that ships.
_REPO_ROOT = Path(__file__).resolve().parents[2]
_SP_SPEC_PATH = _REPO_ROOT / "dist" / "openapi" / "resources" / "SponsoredProducts.json"


@pytest.fixture(scope="module")
def sp_registry() -> MediaTypeRegistry:
    """Load SponsoredProducts.json into a real MediaTypeRegistry.

    Module-scoped to amortize the ~50ms spec parse across every test in the
    file. The registry is treated as read-only.
    """
    if not _SP_SPEC_PATH.exists():
        pytest.skip(
            f"SponsoredProducts spec not found at {_SP_SPEC_PATH}; "
            "build the dist/ tree before running this test."
        )
    with open(_SP_SPEC_PATH) as f:
        spec = json.load(f)
    reg = MediaTypeRegistry()
    reg.add_from_spec(spec)
    return reg


@pytest.fixture(scope="module")
def sp_spec() -> dict:
    """Raw SponsoredProducts spec for tests that walk paths directly."""
    if not _SP_SPEC_PATH.exists():
        pytest.skip(f"SponsoredProducts spec not found at {_SP_SPEC_PATH}")
    with open(_SP_SPEC_PATH) as f:
        return json.load(f)


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
# Mixed-base guard — iterate every op, never crash
# ---------------------------------------------------------------------------


def test_no_operation_in_spec_crashes_resolver(sp_spec: dict) -> None:
    """Walk every operation in the SponsoredProducts spec and confirm the
    resolver returns SOMETHING (a string or None) for every one — never
    crashes. Catches: malformed accepts lists, mixed-base ops we don't know
    about yet, parser regressions on real-world content types.
    """
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
            if not cts:
                continue
            accepts = sorted(cts)
            # Every reasonable existing value should produce SOMETHING (str|None)
            for existing in (None, "*/*", "application/json"):
                result = resolve_accept(
                    spec_accepts=accepts, existing=existing
                )
                assert result is None or isinstance(result, str), (
                    f"{method.upper()} {path} existing={existing!r}: "
                    f"got {type(result).__name__}"
                )


def test_mixed_base_operations_fall_back_to_first_listed(sp_spec: dict) -> None:
    """Find every operation in the spec whose accepts list contains more
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

            # Bucket parsed accepts by base
            from amazon_ads_mcp.utils.media.accept_resolver import (
                parse_vendored_json,
            )

            bases = set()
            for ct in accepts:
                p = parse_vendored_json(ct)
                if p is not None:
                    bases.add(p[0])
            if len(bases) <= 1:
                continue

            found_any = True
            # Picker abstains
            assert pick_highest_vendored_json(accepts) is None, (
                f"{method.upper()} {path}: picker should abstain on "
                f"{len(bases)} bases ({bases}), but returned a value"
            )
            # Resolver falls back to first-listed
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
