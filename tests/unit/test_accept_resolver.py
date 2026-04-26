"""Pure-function tests for the unified Accept-header resolver.

This module exercises ``parse_vendored_json``, ``pick_highest_vendored_json``
and ``resolve_accept`` directly. By contract (see
``docs/roadmap/unified-accept-resolver.md`` — "Source-agnosticism guarantee"),
none of these tests instantiates ``MediaTypeRegistry``: ``spec_accepts`` is
always passed as a list literal so the resolver's policy can never accidentally
couple to a particular data source. The integration test in
``test_accept_resolver_against_spec.py`` is the only place where the resolver
runs against a real registry.
"""

import pytest

from amazon_ads_mcp.utils.media.accept_resolver import (
    parse_vendored_json,
    pick_highest_vendored_json,
    resolve_accept,
)


# ---------------------------------------------------------------------------
# parse_vendored_json
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "ct,expected",
    [
        # Single-segment base
        (
            "application/vnd.spkeywordsrecommendation.v3+json",
            ("spkeywordsrecommendation", 3, 0),
        ),
        # Major.minor
        (
            "application/vnd.insightsbrandmetrics.v1.1+json",
            ("insightsbrandmetrics", 1, 1),
        ),
        # Dotted base (real type from SP spec)
        (
            "application/vnd.spproductrecommendationresponse.asins.v3+json",
            ("spproductrecommendationresponse.asins", 3, 0),
        ),
        # Compound base with mixed case (real type)
        (
            "application/vnd.SponsoredBrands.SponsoredBrandsMigrationApi.v4+json",
            ("sponsoredbrands.sponsoredbrandsmigrationapi", 4, 0),
        ),
        # Hyphen in base — locked by widened character class
        (
            "application/vnd.some-base.v2+json",
            ("some-base", 2, 0),
        ),
        # Underscore in base — locked by widened character class
        (
            "application/vnd.some_base.v2+json",
            ("some_base", 2, 0),
        ),
        # Non-JSON CSV — opaque to picker, parser returns None
        ("text/vnd.measurementresult.v1.2+csv", None),
        # Bare version, no +json — real type from spec, parser intentionally rejects
        ("application/vnd.GlobalRegistrationService.TermsTokenResource.v1", None),
        # Plain JSON — not vendored
        ("application/json", None),
        # Not even close
        ("text/csv", None),
        # Empty / None inputs
        ("", None),
    ],
)
def test_parse_vendored_json_table(ct, expected):
    assert parse_vendored_json(ct) == expected


def test_parse_vendored_json_handles_none_input():
    """Defensive: callers may pass None when accepts list contains gaps."""
    assert parse_vendored_json(None) is None  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# pick_highest_vendored_json
# ---------------------------------------------------------------------------


def test_picker_returns_none_for_empty_list():
    assert pick_highest_vendored_json([]) is None
    assert pick_highest_vendored_json(None) is None  # type: ignore[arg-type]


def test_picker_returns_none_when_no_vendored_json_present():
    assert pick_highest_vendored_json(["application/json", "text/csv"]) is None


def test_picker_single_base_picks_highest_major():
    accepts = [
        "application/vnd.spkeywordsrecommendation.v3+json",
        "application/vnd.spkeywordsrecommendation.v4+json",
        "application/vnd.spkeywordsrecommendation.v5+json",
    ]
    assert (
        pick_highest_vendored_json(accepts)
        == "application/vnd.spkeywordsrecommendation.v5+json"
    )


def test_picker_single_base_is_order_independent():
    accepts = [
        "application/vnd.x.v5+json",
        "application/vnd.x.v3+json",
        "application/vnd.x.v4+json",
    ]
    assert pick_highest_vendored_json(accepts) == "application/vnd.x.v5+json"


def test_picker_major_minor_highest_minor_wins():
    accepts = [
        "application/vnd.x.v1.0+json",
        "application/vnd.x.v1.2+json",
        "application/vnd.x.v1.1+json",
    ]
    assert pick_highest_vendored_json(accepts) == "application/vnd.x.v1.2+json"


def test_picker_major_beats_minor():
    accepts = [
        "application/vnd.x.v1.99+json",
        "application/vnd.x.v2.0+json",
    ]
    assert pick_highest_vendored_json(accepts) == "application/vnd.x.v2.0+json"


def test_picker_abstains_on_mixed_bases():
    """Real case: SP declares both spproductrecommendationresponse.asins and
    .themes on the same operation. Picker cannot decide between two semantic
    shapes by version comparison alone — returns None so resolve_accept rule 4
    falls back to first-listed.
    """
    accepts = [
        "application/vnd.spproductrecommendationresponse.asins.v3+json",
        "application/vnd.spproductrecommendationresponse.themes.v3+json",
    ]
    assert pick_highest_vendored_json(accepts) is None


def test_picker_abstains_on_mixed_bases_even_with_version_difference():
    accepts = [
        "application/vnd.foo.v3+json",
        "application/vnd.bar.v5+json",
    ]
    assert pick_highest_vendored_json(accepts) is None


def test_picker_ignores_non_json_when_mixed_with_json():
    """JSON-only contract: a CSV variant alongside a JSON variant doesn't
    confuse the picker — the CSV is invisible to it."""
    accepts = [
        "application/vnd.x.v1+json",
        "text/vnd.x.v1.2+csv",
    ]
    assert pick_highest_vendored_json(accepts) == "application/vnd.x.v1+json"


# ---------------------------------------------------------------------------
# resolve_accept — the locked policy table from the roadmap doc
# ---------------------------------------------------------------------------


def test_empty_inputs_return_none():
    assert resolve_accept(spec_accepts=None, existing=None) is None


def test_missing_accept_with_single_vendored_returns_vendored():
    assert (
        resolve_accept(
            spec_accepts=["application/vnd.spCampaign.v3+json"],
            existing=None,
        )
        == "application/vnd.spCampaign.v3+json"
    )


def test_star_accept_with_single_vendored_returns_vendored():
    assert (
        resolve_accept(
            spec_accepts=["application/vnd.spCampaign.v3+json"],
            existing="*/*",
        )
        == "application/vnd.spCampaign.v3+json"
    )


def test_non_vendored_existing_with_vendored_available_upgrades():
    """The most controversial rule from PR #68's should_override boolean,
    now explicit and tested."""
    assert (
        resolve_accept(
            spec_accepts=["application/vnd.spCampaign.v3+json"],
            existing="application/json",
        )
        == "application/vnd.spCampaign.v3+json"
    )


def test_caller_pinned_vendored_is_preserved():
    """Rule 1 absolute. Caller picked v2 explicitly; resolver doesn't second-guess."""
    assert (
        resolve_accept(
            spec_accepts=[
                "application/vnd.tpg.v1+json",
                "application/vnd.tpg.v2+json",
            ],
            existing="application/vnd.tpg.v2+json",
        )
        is None
    )


def test_caller_pinned_vendored_preserved_even_if_lower_than_spec():
    """Rule 1 holds even when caller-pinned version is OLDER than spec offers."""
    assert (
        resolve_accept(
            spec_accepts=["application/vnd.tpg.v2+json"],
            existing="application/vnd.tpg.v1+json",
        )
        is None
    )


def test_multi_version_highest_wins():
    """The headline regression fix this PR exists for."""
    accepts = [
        "application/vnd.spkeywordsrecommendation.v3+json",
        "application/vnd.spkeywordsrecommendation.v4+json",
        "application/vnd.spkeywordsrecommendation.v5+json",
    ]
    assert (
        resolve_accept(spec_accepts=accepts, existing="*/*")
        == "application/vnd.spkeywordsrecommendation.v5+json"
    )


def test_multi_version_highest_wins_regardless_of_input_order():
    accepts = [
        "application/vnd.x.v5+json",
        "application/vnd.x.v3+json",
        "application/vnd.x.v4+json",
    ]
    assert (
        resolve_accept(spec_accepts=accepts, existing="*/*")
        == "application/vnd.x.v5+json"
    )


def test_major_minor_highest_minor_wins():
    accepts = [
        "application/vnd.x.v1.0+json",
        "application/vnd.x.v1.2+json",
        "application/vnd.x.v1.1+json",
    ]
    assert (
        resolve_accept(spec_accepts=accepts, existing="*/*")
        == "application/vnd.x.v1.2+json"
    )


def test_major_beats_minor():
    accepts = [
        "application/vnd.x.v1.99+json",
        "application/vnd.x.v2.0+json",
    ]
    assert (
        resolve_accept(spec_accepts=accepts, existing="*/*")
        == "application/vnd.x.v2.0+json"
    )


def test_dotted_base_resolves_correctly():
    """Real spec type — verifies widened regex flows through the resolver."""
    assert (
        resolve_accept(
            spec_accepts=[
                "application/vnd.spproductrecommendationresponse.asins.v3+json"
            ],
            existing=None,
        )
        == "application/vnd.spproductrecommendationresponse.asins.v3+json"
    )


def test_compound_base_resolves_correctly():
    """Compound base from real SponsoredBrands spec."""
    assert (
        resolve_accept(
            spec_accepts=[
                "application/vnd.SponsoredBrands.SponsoredBrandsMigrationApi.v4+json"
            ],
            existing=None,
        )
        == "application/vnd.SponsoredBrands.SponsoredBrandsMigrationApi.v4+json"
    )


def test_mixed_bases_falls_back_to_first_listed():
    """Picker abstains; rule 4 returns first-listed (after registry's lexical sort)."""
    accepts = [
        "application/vnd.x.asins.v3+json",
        "application/vnd.x.themes.v3+json",
    ]
    assert (
        resolve_accept(spec_accepts=accepts, existing="*/*")
        == "application/vnd.x.asins.v3+json"
    )


def test_mixed_bases_with_version_difference_falls_back_to_first_listed():
    """Picker abstains because two distinct bases — rule 4 gets first-listed."""
    accepts = [
        "application/vnd.bar.v5+json",
        "application/vnd.foo.v3+json",
    ]
    assert (
        resolve_accept(spec_accepts=accepts, existing="*/*")
        == "application/vnd.bar.v5+json"
    )


def test_no_vendored_spec_accepts_with_missing_existing():
    """Rule 4 fallback when spec has values but no vendored JSON."""
    assert (
        resolve_accept(spec_accepts=["application/json"], existing=None)
        == "application/json"
    )


def test_download_override_intersects_spec_wins_over_highest():
    """Rule 2: the download contract is more specific than the spec's
    'highest' heuristic. Even though the picker would pick v1 here too,
    rule 2 fires first and bypasses the picker."""
    assert (
        resolve_accept(
            spec_accepts=[
                "application/vnd.adsexport.v1+json",
                "application/json",
            ],
            existing=None,
            download_overrides=["application/vnd.adsexport.v1+json"],
        )
        == "application/vnd.adsexport.v1+json"
    )


def test_download_override_does_not_intersect_spec_picker_wins():
    """Rule 2 misses (no intersection); rule 3 picks highest vendored."""
    assert (
        resolve_accept(
            spec_accepts=["application/vnd.spCampaign.v3+json"],
            existing="*/*",
            download_overrides=["text/csv"],
        )
        == "application/vnd.spCampaign.v3+json"
    )


def test_download_override_only_no_spec_returns_first():
    """Rule 5: no spec data, take overrides[0]."""
    assert (
        resolve_accept(
            spec_accepts=None,
            existing="*/*",
            download_overrides=["text/csv"],
        )
        == "text/csv"
    )


def test_caller_pinned_beats_download_override():
    """Rule 1 is absolute — even download_overrides cannot displace
    a caller-pinned vendored Accept."""
    assert (
        resolve_accept(
            spec_accepts=["application/vnd.x.v1+json"],
            existing="application/vnd.x.v1+json",
            download_overrides=["application/json"],
        )
        is None
    )


def test_whitespace_only_existing_treated_as_missing():
    assert (
        resolve_accept(
            spec_accepts=["application/vnd.x.v1+json"],
            existing="   ",
        )
        == "application/vnd.x.v1+json"
    )


def test_padded_star_treated_as_star():
    assert (
        resolve_accept(
            spec_accepts=["application/vnd.x.v1+json"],
            existing=" */* ",
        )
        == "application/vnd.x.v1+json"
    )


def test_non_json_vendored_only_returns_first_listed():
    """text/vnd.…+csv is opaque to the picker (not +json). Rule 4 fires:
    spec has values, picker returned None, existing is generic → first-listed.
    The resolver stays neutral on non-JSON semantics; the download path
    handles CSV elsewhere."""
    assert (
        resolve_accept(
            spec_accepts=["text/vnd.measurementresult.v1.2+csv"],
            existing="*/*",
        )
        == "text/vnd.measurementresult.v1.2+csv"
    )


def test_non_vendored_existing_with_no_spec_accepts_unchanged():
    """No spec data, no download data — leave whatever caller set alone."""
    assert (
        resolve_accept(
            spec_accepts=None,
            existing="application/json",
        )
        is None
    )


def test_non_vendored_existing_with_no_vendored_in_spec_unchanged():
    """Caller set application/json, spec also only knows application/json.
    Nothing to upgrade to → leave alone."""
    assert (
        resolve_accept(
            spec_accepts=["application/json"],
            existing="application/json",
        )
        is None
    )


# ---------------------------------------------------------------------------
# Rule 4: non-version vendored types (e.g. xlsx mime) preserved over generic
# ---------------------------------------------------------------------------


def test_non_version_vendored_in_spec_beats_application_json():
    """Real case from existing test_authenticated_client.test_media_type_negotiation:
    spec advertises an xlsx-style vendored type alongside application/json.
    Picker abstains (no +json suffix), but rule 4 returns the vendored value.
    Without this rule, the registry's lexical sort would put application/json
    first and rule 5 would return it instead — losing the vendored intent."""
    accepts = [
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/json",
    ]
    assert (
        resolve_accept(spec_accepts=accepts, existing="*/*")
        == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )


def test_non_version_vendored_wins_regardless_of_spec_order():
    """Same as above but with json first (post-lexical-sort order)."""
    accepts = [
        "application/json",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ]
    assert (
        resolve_accept(spec_accepts=accepts, existing="*/*")
        == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )


# ---------------------------------------------------------------------------
# Rule 2 hardening: only VENDORED intersections count
# ---------------------------------------------------------------------------


def test_non_vendored_download_intersection_does_not_clobber_vendored_pick():
    """The download resolver returns ['application/json'] as a default for
    unrecognized download endpoints. If we treated that as authoritative
    intersection, we'd downgrade a vendored spec accept to application/json.
    Rule 2 only counts intersections on vendored values, so the default
    fallback can't suppress rule 3/4."""
    assert (
        resolve_accept(
            spec_accepts=[
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                "application/json",
            ],
            existing="*/*",
            download_overrides=["application/json"],  # default fallback only
        )
        == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )


def test_vendored_download_intersection_still_wins_over_picker():
    """The export endpoint case: download resolver knows the specific vendored
    type the endpoint serves; that wins over highest-version selection."""
    assert (
        resolve_accept(
            spec_accepts=[
                "application/vnd.campaignsexport.v1+json",
                "application/json",
            ],
            existing="*/*",
            download_overrides=[
                "application/vnd.campaignsexport.v1+json",
                "application/json",
            ],
        )
        == "application/vnd.campaignsexport.v1+json"
    )


def test_text_vendored_download_intersection_wins():
    """text/vnd.* counts as vendored for rule 2 intersection (CSV exports)."""
    assert (
        resolve_accept(
            spec_accepts=[
                "text/vnd.measurementresult.v1.2+csv",
                "application/json",
            ],
            existing="*/*",
            download_overrides=["text/vnd.measurementresult.v1.2+csv"],
        )
        == "text/vnd.measurementresult.v1.2+csv"
    )
