"""Property-based tests for the Accept-header resolver.

Complement to ``test_accept_resolver.py`` (example-based) and
``test_accept_resolver_against_spec.py`` (spec-corpus). These tests encode
the *invariants* documented in ``accept_resolver.py`` and verify them
against many randomly generated inputs.

Why property-based here:
- ``resolve_accept`` is pure with a 7-rule policy → small fingerprint, large
  behavioral surface. Example tests can only sample it.
- ``parse_vendored_json`` has a regex that's been tightened twice for
  real-world spec quirks (compound bases, dotted bases). Random fuzzing
  catches regex drift that example tests miss.
- Hypothesis shrinks failures to minimal counter-examples, so any future
  regression surfaces with the smallest reproducer.
"""

from __future__ import annotations

import re

import pytest
from hypothesis import HealthCheck, assume, example, given, settings
from hypothesis import strategies as st

from amazon_ads_mcp.utils.media.accept_resolver import (
    parse_vendored_json,
    pick_highest_vendored_json,
    resolve_accept,
)

# --- Strategies -----------------------------------------------------------

# Match the production regex's allowed base chars EXACTLY.
# The regex is `[A-Za-z0-9._-]+` — ASCII only.
# Hypothesis caught this on first run: a Unicode-letter strategy
# (whitelist_categories=("Ll", "Lu", "Nd")) generated `µ` (U+00B5),
# which is `Ll` but not ASCII, and produced a "production bug" that
# was actually a strategy/contract mismatch. Strategies must mirror
# the contract, not assume the contract.
_base_alphabet = st.text(
    alphabet=st.sampled_from(
        list("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-")
    ),
    min_size=1,
    max_size=20,
)


@st.composite
def vendored_json_ct(draw):
    """Generate a well-formed ``application/vnd.<base>.v<M>[.<m>]+json``.

    Bases are non-empty and stay within the regex's accepted alphabet.
    Versions are small non-negative integers.
    """
    base = draw(_base_alphabet)
    # Ensure the base does not start/end with a separator and is not all
    # separators — the regex permits it but it's not a realistic spec value
    # and it makes shrinks ugly.
    assume(base[0].isalnum() and base[-1].isalnum())
    major = draw(st.integers(min_value=0, max_value=99))
    has_minor = draw(st.booleans())
    if has_minor:
        minor = draw(st.integers(min_value=0, max_value=99))
        return f"application/vnd.{base}.v{major}.{minor}+json"
    return f"application/vnd.{base}.v{major}+json"


# Arbitrary content-type-ish strings, including malformed ones, for fuzzing
# parse_vendored_json's failure path.
arbitrary_ct = st.one_of(
    st.text(max_size=80),
    vendored_json_ct(),
    st.sampled_from([
        "application/json",
        "*/*",
        "text/csv",
        "text/vnd.measurementresult.v1.2+csv",
        "application/vnd.openxmlformats.sheet",
        "application/vnd.foo.bar.v1+xml",  # +xml not +json
        "application/vnd..v1+json",  # empty base (regex should reject)
        "",
    ]),
)


# --- parse_vendored_json --------------------------------------------------


@given(vendored_json_ct())
@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
def test_parse_vendored_json_roundtrip_on_well_formed(ct: str) -> None:
    """Any generated vendored-json content type parses successfully and the
    parsed (base, M, m) reconstructs to a string that parses to the same."""
    parsed = parse_vendored_json(ct)
    assert parsed is not None, f"failed to parse generated CT: {ct!r}"
    base, major, minor = parsed
    # base is lowercased by parse — round-trip via reconstructed CT
    rebuilt = (
        f"application/vnd.{base}.v{major}.{minor}+json"
        if minor
        else f"application/vnd.{base}.v{major}+json"
    )
    rebuilt_parsed = parse_vendored_json(rebuilt)
    assert rebuilt_parsed == (base, major, minor)


@given(arbitrary_ct)
@settings(max_examples=300)
def test_parse_vendored_json_never_raises(ct: str) -> None:
    """Arbitrary string input must never raise — invalid → None."""
    result = parse_vendored_json(ct)
    assert result is None or (
        isinstance(result, tuple)
        and len(result) == 3
        and isinstance(result[0], str)
        and isinstance(result[1], int)
        and isinstance(result[2], int)
    )


@given(st.text(max_size=80))
def test_parse_vendored_json_rejects_non_vendored(ct: str) -> None:
    """Strings that don't start with the vendored prefix must return None."""
    if not ct.startswith("application/vnd."):
        assert parse_vendored_json(ct) is None


# --- pick_highest_vendored_json ------------------------------------------


@given(st.lists(vendored_json_ct(), min_size=1, max_size=10))
@settings(max_examples=200)
def test_picker_returns_one_of_inputs_when_single_base(cts: list[str]) -> None:
    """If the picker returns non-None, the result must be one of the inputs."""
    # Force single-base by reducing all entries to share the first's base.
    parsed_first = parse_vendored_json(cts[0])
    assert parsed_first is not None
    base = parsed_first[0]
    # Rebuild the list with the same base (preserves versions but unifies base)
    unified: list[str] = []
    for ct in cts:
        p = parse_vendored_json(ct)
        assert p is not None
        _, m, mn = p
        unified.append(
            f"application/vnd.{base}.v{m}.{mn}+json" if mn else f"application/vnd.{base}.v{m}+json"
        )
    result = pick_highest_vendored_json(unified)
    assert result is not None
    assert result in unified


@given(st.lists(vendored_json_ct(), min_size=2, max_size=10))
@settings(max_examples=200)
def test_picker_chooses_highest_version(cts: list[str]) -> None:
    """When all inputs share a base, the result has the maximal (M, m)."""
    parsed_first = parse_vendored_json(cts[0])
    assert parsed_first is not None
    base = parsed_first[0]
    unified: list[str] = []
    for ct in cts:
        p = parse_vendored_json(ct)
        assert p is not None
        _, m, mn = p
        unified.append(
            f"application/vnd.{base}.v{m}.{mn}+json" if mn else f"application/vnd.{base}.v{m}+json"
        )

    result = pick_highest_vendored_json(unified)
    assert result is not None
    result_parsed = parse_vendored_json(result)
    assert result_parsed is not None
    _, r_major, r_minor = result_parsed

    expected_max = max(
        ((parse_vendored_json(c) or (base, 0, 0))[1:3]) for c in unified
    )
    assert (r_major, r_minor) == expected_max


def test_picker_returns_none_for_mixed_bases() -> None:
    """Documented invariant: mixed bases → abstain (None)."""
    cts = [
        "application/vnd.alpha.v1+json",
        "application/vnd.beta.v2+json",
    ]
    assert pick_highest_vendored_json(cts) is None


@given(st.lists(st.text(max_size=40), max_size=10))
def test_picker_returns_none_when_no_vendored_json(cts: list[str]) -> None:
    """Inputs with zero parseable vendored-json types → None."""
    assume(all(parse_vendored_json(ct) is None for ct in cts))
    assert pick_highest_vendored_json(cts) is None


# --- resolve_accept -------------------------------------------------------


@given(
    existing=st.one_of(st.none(), vendored_json_ct()),
    spec=st.one_of(st.none(), st.lists(vendored_json_ct(), min_size=0, max_size=5)),
    overrides=st.one_of(st.none(), st.lists(arbitrary_ct, min_size=0, max_size=5)),
)
@settings(max_examples=300)
def test_caller_pinned_vendored_is_preserved(
    existing: str | None, spec: list[str] | None, overrides: list[str] | None
) -> None:
    """Rule 1: if ``existing`` is vendored, return None unconditionally."""
    if existing is None or not existing.startswith("application/vnd."):
        return  # not the case under test
    result = resolve_accept(
        spec_accepts=spec,
        existing=existing,
        download_overrides=overrides,
    )
    assert result is None, (
        f"caller-pinned {existing!r} must be preserved (got {result!r})"
    )


@given(arbitrary_ct, arbitrary_ct, arbitrary_ct)
@settings(max_examples=300, suppress_health_check=[HealthCheck.filter_too_much])
def test_resolve_accept_never_raises(a: str, b: str, c: str) -> None:
    """Arbitrary string inputs must not raise; output is str-or-None."""
    result = resolve_accept(
        spec_accepts=[a, b],
        existing=c,
        download_overrides=[a],
    )
    assert result is None or isinstance(result, str)


@given(
    spec=st.lists(vendored_json_ct(), min_size=1, max_size=5),
)
@settings(max_examples=150)
def test_resolve_idempotent_when_existing_matches_resolved(spec: list[str]) -> None:
    """Feeding the resolved value back as ``existing`` returns None.

    This is the "agreement" property: once the resolver has chosen, the
    caller's new ``Accept`` is honored as caller-pinned and not modified
    again on retry.
    """
    first = resolve_accept(spec_accepts=spec, existing=None)
    if first is None or not first.startswith("application/vnd."):
        return  # only meaningful when resolver picked a vendored value
    second = resolve_accept(spec_accepts=spec, existing=first)
    assert second is None


# Regression anchors — keep these as concrete examples even though the
# properties above cover them; they make CI failures self-explanatory.
@example("application/vnd.spCampaign.v3+json")
@example("application/vnd.SponsoredBrands.SponsoredBrandsMigrationApi.v1+json")
@example("application/vnd.spproductrecommendationresponse.asins.v2+json")
@given(vendored_json_ct())
def test_real_world_compound_bases_parse(ct: str) -> None:
    """The parser must accept dotted/compound bases that real specs use."""
    assert parse_vendored_json(ct) is not None
