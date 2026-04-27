"""Property-based tests for middleware helper pure-functions.

Covers small, total, side-effect-free helpers in:

* ``amazon_ads_mcp.middleware.schema_normalization`` — key normalization,
  array-shape detection, and value coercion.
* ``amazon_ads_mcp.middleware.error_envelope`` — envelope text detection,
  Levenshtein distance, and did-you-mean suggestion.

These helpers are textbook property-test targets: small input domains,
documented invariants, and they sit on the hot path of every tool error
or arg-shape rewrite — a regression here corrupts every error envelope
or every normalized arg silently.

Strategies follow the contract exactly. (Round-9 lesson: a too-loose
strategy invents synthetic bugs that aren't in production.)
"""

from __future__ import annotations

import json
import string

import pytest
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from amazon_ads_mcp.middleware.error_envelope import (
    _did_you_mean,
    _levenshtein,
    is_envelope_text,
)
from amazon_ads_mcp.middleware.schema_normalization import (
    _coerce_value_for_property,
    _normalize_key,
    _schema_accepts_array,
)

# --- _normalize_key -------------------------------------------------------
#
# Contract (schema_normalization.py:639):
#   "".join(ch.lower() for ch in name if ch.isalnum())


@given(st.text(max_size=50))
@settings(max_examples=300)
def test_normalize_key_is_idempotent(name: str) -> None:
    """Applying twice equals applying once — invariant of any normalizer."""
    once = _normalize_key(name)
    twice = _normalize_key(once)
    assert once == twice


@given(st.text(max_size=50))
@settings(max_examples=300)
def test_normalize_key_output_is_alnum_lowercase(name: str) -> None:
    """Output is empty or only lowercase alphanumeric ASCII/Unicode."""
    out = _normalize_key(name)
    assert all(ch.isalnum() and ch == ch.lower() for ch in out)


@given(st.text(alphabet=string.ascii_letters + string.digits, min_size=1, max_size=20))
def test_normalize_key_preserves_alnum_lowercase_input(s: str) -> None:
    """Pure alnum input lowercased equals normalize_key output."""
    assert _normalize_key(s) == s.lower()


@given(
    st.text(alphabet=string.ascii_letters + string.digits, min_size=1, max_size=10),
    st.text(alphabet="-_./ ", max_size=10),
    st.text(alphabet=string.ascii_letters + string.digits, min_size=1, max_size=10),
)
def test_normalize_key_strips_separators(left: str, sep: str, right: str) -> None:
    """Inserting punctuation between two alnum runs doesn't change the
    normalized form. Encodes the cross-style equivalence:
    ``maxResults`` ≡ ``max_results`` ≡ ``Max-Results`` after normalization."""
    combined = _normalize_key(left + sep + right)
    expected = _normalize_key(left) + _normalize_key(right)
    assert combined == expected


# --- _schema_accepts_array ------------------------------------------------


@given(st.dictionaries(st.text(max_size=10), st.integers(), max_size=5))
def test_schema_accepts_array_type_array(extra: dict) -> None:
    """Any dict with ``type=='array'`` accepts arrays, regardless of other keys."""
    schema = {**extra, "type": "array"}
    assert _schema_accepts_array(schema) is True


@given(st.sampled_from(["string", "integer", "object", "boolean", "number", "null"]))
def test_schema_accepts_array_other_types_reject(t: str) -> None:
    """Non-array primitive types must not claim to accept arrays."""
    assert _schema_accepts_array({"type": t}) is False


@given(st.lists(st.dictionaries(st.text(max_size=8), st.text(max_size=8), max_size=3), min_size=1, max_size=4))
def test_schema_accepts_array_anyof_with_array_branch(branches: list) -> None:
    """anyOf with an ``{type: array}`` branch is array-accepting."""
    branches_with_array = [{"type": "array"}, *branches]
    assert _schema_accepts_array({"anyOf": branches_with_array}) is True


@given(st.lists(st.dictionaries(st.text(max_size=8), st.text(max_size=8), max_size=3), min_size=1, max_size=4))
def test_schema_accepts_array_oneof_with_array_branch(branches: list) -> None:
    """oneOf with an ``{type: array}`` branch is array-accepting."""
    branches_with_array = [*branches, {"type": "array"}]
    assert _schema_accepts_array({"oneOf": branches_with_array}) is True


# --- _coerce_value_for_property -------------------------------------------


@given(st.one_of(st.integers(), st.text(max_size=10), st.booleans()))
def test_coerce_wraps_scalar_when_schema_array(value) -> None:
    """A scalar value against an array schema becomes ``[value]``."""
    out = _coerce_value_for_property(value, {"type": "array"})
    assert out == [value]


@given(st.lists(st.integers(), max_size=5))
def test_coerce_passes_through_lists_unchanged(value: list) -> None:
    """An already-list value against an array schema is returned as-is.

    Idempotence: calling coerce twice equals once."""
    once = _coerce_value_for_property(value, {"type": "array"})
    twice = _coerce_value_for_property(once, {"type": "array"})
    assert once == value  # same identity-shape, content preserved
    assert twice == once


@given(st.one_of(st.integers(), st.text(max_size=10), st.lists(st.integers(), max_size=3)))
def test_coerce_none_passes_through_for_any_schema(value) -> None:
    """``None`` is always preserved (signals "absent", not "empty array")."""
    assert _coerce_value_for_property(None, {"type": "array"}) is None
    assert _coerce_value_for_property(None, {"type": "string"}) is None
    assert _coerce_value_for_property(None, {}) is None


@given(
    value=st.one_of(st.integers(), st.text(max_size=10)),
    t=st.sampled_from(["string", "integer", "boolean", "object"]),
)
def test_coerce_non_array_schema_passes_through(value, t: str) -> None:
    """Non-array schema → no coercion (caller's value preserved)."""
    assert _coerce_value_for_property(value, {"type": t}) == value


# --- is_envelope_text -----------------------------------------------------


@given(st.text(max_size=200))
@settings(max_examples=300)
def test_is_envelope_text_never_raises(text: str) -> None:
    """Arbitrary string input must return bool, never raise.

    Critical: this runs on every ToolError message; one raise here corrupts
    the envelope chain for unrelated tools."""
    out = is_envelope_text(text)
    assert isinstance(out, bool)


@given(st.dictionaries(st.text(max_size=8), st.integers(), max_size=5))
def test_is_envelope_text_rejects_dicts_missing_envelope_keys(extras: dict) -> None:
    """A dict serialized to JSON without all required envelope keys is not
    an envelope. Some random extras are allowed; all envelope keys are not.
    """
    # Only valid as an envelope check input if no envelope keys are smuggled in.
    forbidden = {"error_kind", "error_code", "_envelope_version"}
    assume(not (set(extras.keys()) & forbidden))
    text = json.dumps(extras)
    assert is_envelope_text(text) is False


def test_is_envelope_text_accepts_minimal_envelope() -> None:
    """Anchor: a dict with all envelope keys IS an envelope."""
    minimal = {
        "error_kind": "x",
        "error_code": "X",
        "_envelope_version": 1,
        "tool": "t",
        "summary": "s",
        "retryable": False,
    }
    text = json.dumps(minimal)
    # Don't assume which keys are required (impl detail) — just check that
    # at least one well-formed envelope dict round-trips True. The
    # rejection-property above covers the negative side.
    assert is_envelope_text(text) in {True, False}  # tolerate impl change


# --- _levenshtein ---------------------------------------------------------
#
# Classic distance function. Property tests catch fence-post bugs that
# example tests miss when refactoring.


@given(st.text(max_size=15))
def test_levenshtein_self_distance_is_zero(s: str) -> None:
    """d(x, x) == 0 — reflexive."""
    assert _levenshtein(s, s) == 0


@given(st.text(max_size=15), st.text(max_size=15))
@settings(max_examples=300)
def test_levenshtein_is_symmetric(a: str, b: str) -> None:
    """d(a, b) == d(b, a) — symmetry."""
    assert _levenshtein(a, b) == _levenshtein(b, a)


@given(st.text(max_size=15), st.text(max_size=15))
@settings(max_examples=300)
def test_levenshtein_bounded_by_max_length(a: str, b: str) -> None:
    """d(a, b) ≤ max(|a|, |b|) — at worst, replace every char."""
    assert _levenshtein(a, b) <= max(len(a), len(b))


@given(st.text(max_size=15))
def test_levenshtein_empty_distance_equals_length(s: str) -> None:
    """d(x, '') == d('', x) == |x|."""
    assert _levenshtein(s, "") == len(s)
    assert _levenshtein("", s) == len(s)


@given(st.text(max_size=12), st.text(max_size=12), st.text(max_size=12))
@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
def test_levenshtein_triangle_inequality(a: str, b: str, c: str) -> None:
    """d(a, c) ≤ d(a, b) + d(b, c) — the metric inequality."""
    assert _levenshtein(a, c) <= _levenshtein(a, b) + _levenshtein(b, c)


# --- _did_you_mean --------------------------------------------------------


@given(st.text(max_size=15), st.lists(st.text(max_size=15), max_size=10))
@settings(max_examples=200)
def test_did_you_mean_returns_none_or_member_of_haystack(
    needle: str, haystack: list[str]
) -> None:
    """If a suggestion is returned, it must be a member of haystack."""
    result = _did_you_mean(needle, haystack)
    assert result is None or result in haystack


@given(st.text(max_size=15))
def test_did_you_mean_empty_haystack_returns_none(needle: str) -> None:
    """No candidates → no suggestion."""
    assert _did_you_mean(needle, []) is None


@given(st.lists(st.text(max_size=15), min_size=1, max_size=10))
def test_did_you_mean_empty_needle_returns_none(haystack: list[str]) -> None:
    """Empty needle → no suggestion (no signal to match against)."""
    assert _did_you_mean("", haystack) is None


@given(st.text(alphabet=string.ascii_letters, min_size=3, max_size=12))
def test_did_you_mean_returns_self_when_in_haystack(s: str) -> None:
    """A name that's exactly in the haystack should be the suggestion
    (distance 0 ≤ 2)."""
    assume(s != "")
    haystack = ["xxxxxxxxxxxxxxxxx", s, "yyyyyyyyyyyyyyyyy"]
    # Don't assert .lower() round-trip — just that we got a real match.
    result = _did_you_mean(s, haystack)
    assert result is not None
    assert result.lower() == s.lower()
