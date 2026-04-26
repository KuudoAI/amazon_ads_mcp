"""Round 3-C: hint quality on Ads ``mcp_input_validation`` envelopes.

Tester reports:

- Missing required field → generic "Check required fields..." instead of
  "Required field missing: 'identity_id'" naming the actual field.
- Typo on field name (``limt`` instead of ``limit``) → generic boilerplate
  instead of a "Did you mean 'limit'?" hint with Levenshtein-suggested
  correction.

The ``details`` array already contains the path and issue strings; promote
them into the hints so an agent gets the specific guidance up-front.
"""

from __future__ import annotations


from pydantic import BaseModel, ValidationError

from amazon_ads_mcp.middleware.error_envelope import build_envelope_from_exception


class _NeedsLimit(BaseModel):
    limit: int
    offset: int = 0


def test_missing_required_field_hint_names_field():
    """When Pydantic complains the field is missing, the hint must name it."""
    try:
        _NeedsLimit()
    except ValidationError as exc:
        envelope = build_envelope_from_exception(exc, tool_name="page_profiles")
    hints_text = " ".join(envelope.get("hints", []))
    assert "limit" in hints_text.lower()
    # The hint should call out missing-required explicitly
    assert any("required" in h.lower() and "limit" in h.lower() for h in envelope["hints"])


def test_unexpected_keyword_argument_emits_did_you_mean():
    """When details record an unexpected keyword (typo), suggest a close
    canonical match via Levenshtein when one exists.

    Pydantic emits ``extra forbidden`` when ``model_config`` forbids extras.
    The translator should surface a "Did you mean ...?" hint when the
    typo is within edit distance 2 of a known field.
    """

    class StrictLimit(BaseModel):
        model_config = {"extra": "forbid"}
        limit: int = 10
        offset: int = 0

    try:
        StrictLimit(limt=5)  # typo
    except ValidationError as exc:
        envelope = build_envelope_from_exception(exc, tool_name="page_profiles")
    hints_text = " ".join(envelope.get("hints", []))
    # Either a "did you mean limit" or naming the unexpected key in the hint
    assert "limit" in hints_text.lower()
    assert "did you mean" in hints_text.lower() or "limt" in hints_text.lower()


def test_canonical_baseline_hint_still_present_when_no_specific_guidance():
    """When details don't match the missing-required / typo patterns,
    the generic guidance hint is still emitted as a fallback."""

    class _NeedsInt(BaseModel):
        value: int

    try:
        _NeedsInt(value="oops")
    except ValidationError as exc:
        envelope = build_envelope_from_exception(exc, tool_name="t")
    hints = envelope["hints"]
    assert hints, "must emit at least one hint"
