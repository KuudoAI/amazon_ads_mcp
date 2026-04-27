"""Property-based tests for ``_promote_field_signals_into_hints`` and
``_sanitize_path`` in the error-envelope translator.

These helpers run on every emitted envelope to surface field-level guidance
to the agent ("Required field missing: 'foo'", "Unknown field 'bar'").
A latent bug here either (a) leaks malformed paths into agent-facing text
or (b) raises and breaks the entire envelope chain. Property tests lock
both invariants.
"""

from __future__ import annotations

import string

from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from amazon_ads_mcp.middleware.error_envelope import (
    _promote_field_signals_into_hints,
    _sanitize_path,
)


# --- _sanitize_path --------------------------------------------------------


@given(st.text(max_size=80))
@settings(max_examples=300)
def test_sanitize_path_never_raises(path: str) -> None:
    """Arbitrary input must return str, never raise."""
    out = _sanitize_path(path)
    assert isinstance(out, str)


@given(st.text(max_size=80))
@settings(max_examples=200)
def test_sanitize_path_is_idempotent(path: str) -> None:
    """sanitize(sanitize(x)) == sanitize(x)."""
    once = _sanitize_path(path)
    twice = _sanitize_path(once)
    assert once == twice


# The production contract for _PATH_TRAILING_JUNK (see error_envelope.py:726):
#   " \t\n\r;,.:!?\"'"
# Strategies must mirror this set exactly. Anything outside it (e.g. ")")
# stops the strip and stays attached to the path.
_TRAILING_JUNK_CHARS = " \t\n\r;,.:!?\"'"


@given(st.text(alphabet=string.ascii_letters + "_", min_size=1, max_size=20))
def test_sanitize_path_preserves_clean_input(s: str) -> None:
    """Pure ascii-letter+underscore input is unchanged after sanitization.

    Note: dots (``.``) are intentionally excluded from this strategy
    because trailing ``.`` is part of the strip-set (e.g. pydantic emits
    paths like ``foo.bar.``). That's tested separately by the trailing-
    punctuation property.
    """
    assume(not (s.startswith(("'", '"')) and s.endswith(("'", '"'))))
    assert _sanitize_path(s) == s


@given(st.text(alphabet=string.ascii_letters, min_size=1, max_size=15))
def test_sanitize_path_strips_matching_quotes(s: str) -> None:
    """Both single- and double-quote wrappers must be stripped."""
    for q in ("'", '"'):
        assert _sanitize_path(f"{q}{s}{q}") == s


@given(st.text(alphabet=string.ascii_letters, min_size=1, max_size=15))
def test_sanitize_path_strips_trailing_punctuation(s: str) -> None:
    """Trailing chars in the documented strip-set are removed.

    Set comes from ``error_envelope._PATH_TRAILING_JUNK`` (round 13:
    Hypothesis caught my first draft using ``".)"``, which fails
    because ``)`` is intentionally NOT in the strip-set — strategies
    must mirror the contract exactly).
    """
    for trailing in (";", ":", ".", ",", "; ", "..", ";;"):
        assert _sanitize_path(s + trailing) == s


# --- _promote_field_signals_into_hints ------------------------------------


def _envelope_with_details(details: list, hints: list | None = None) -> dict:
    """Build a minimal envelope dict shaped enough for the promotion pass."""
    return {
        "error_kind": "mcp_input_validation",
        "error_code": "VALIDATION",
        "tool": "test_tool",
        "summary": "test",
        "details": details,
        "hints": hints if hints is not None else [],
        "examples": [],
        "retryable": False,
        "_envelope_version": 1,
    }


@given(st.text(max_size=40))
@settings(max_examples=200)
def test_promote_never_raises_on_arbitrary_envelope_shape(garbage: str) -> None:
    """The promotion pass must tolerate malformed envelopes — it runs
    AFTER classification and must not break the chain."""
    # Various malformed shapes the function must survive:
    bad_envelopes = [
        {"details": garbage},
        {"details": None},
        {"details": [garbage]},
        {"details": [{"path": garbage, "issue": garbage}]},
        {"details": [None, "string", 42, {}]},
        {"hints": garbage, "details": []},
        {},  # No keys at all
    ]
    for env in bad_envelopes:
        # Must not raise; must not corrupt the dict beyond shape.
        _promote_field_signals_into_hints(env)


@given(
    field_name=st.text(
        alphabet=string.ascii_letters + "_", min_size=1, max_size=20
    ),
)
@settings(max_examples=150)
def test_missing_field_signal_produces_required_hint(field_name: str) -> None:
    """A details entry signalling missing/required field promotes to
    "Required field missing: 'X'"."""
    for marker in ("missing", "required", "Field required"):
        env = _envelope_with_details([
            {"path": field_name, "issue": f"value is {marker}"}
        ])
        _promote_field_signals_into_hints(env)
        assert any(
            f"Required field missing: '{field_name}'" in h
            for h in env["hints"]
        ), f"missing hint for marker {marker!r}, got hints={env['hints']!r}"


@given(
    field_name=st.text(
        alphabet=string.ascii_letters + "_", min_size=1, max_size=20
    ),
)
@settings(max_examples=150)
def test_unknown_field_signal_produces_unknown_hint(field_name: str) -> None:
    """A details entry signalling extra/unknown/forbidden promotes to
    "Unknown field 'X'"."""
    for marker in ("extra", "unexpected", "not permitted", "forbidden", "unknown"):
        env = _envelope_with_details([
            {"path": field_name, "issue": f"value is {marker}"}
        ])
        _promote_field_signals_into_hints(env)
        assert any(
            f"Unknown field '{field_name}'" in h for h in env["hints"]
        ), f"missing hint for marker {marker!r}"


@given(
    field_name=st.text(
        alphabet=string.ascii_letters, min_size=1, max_size=15
    ),
)
def test_promoted_hints_are_deduplicated(field_name: str) -> None:
    """Duplicate details entries for the same path produce ONE hint, not N.

    Critical: agents waste tokens chasing repeated suggestions; one
    "Required field missing: 'foo'" is enough."""
    env = _envelope_with_details([
        {"path": field_name, "issue": "missing"},
        {"path": field_name, "issue": "missing"},
        {"path": field_name, "issue": "required"},
    ])
    _promote_field_signals_into_hints(env)
    matching = [
        h for h in env["hints"]
        if f"Required field missing: '{field_name}'" in h
    ]
    assert len(matching) == 1, f"expected 1 hint, got {len(matching)}"


@given(
    field_name=st.text(
        alphabet=string.ascii_letters, min_size=1, max_size=15
    ),
    existing_hints=st.lists(st.text(max_size=30), max_size=5),
)
@settings(max_examples=100)
def test_promoted_hints_prepended_to_existing(
    field_name: str, existing_hints: list[str]
) -> None:
    """Promoted hints come FIRST in the hints list — agents read top-down."""
    env = _envelope_with_details(
        [{"path": field_name, "issue": "missing"}],
        hints=list(existing_hints),
    )
    _promote_field_signals_into_hints(env)
    promoted = f"Required field missing: '{field_name}'."
    assert env["hints"][0] == promoted


@given(st.text(max_size=20))
def test_promote_no_signal_no_change(noise: str) -> None:
    """Details without missing/required/extra keywords leave hints unchanged.

    Locks against false-positive promotion that would litter every error
    envelope with bogus "Required field" suggestions."""
    env = _envelope_with_details([
        {"path": "foo", "issue": noise},
    ])
    # Filter out cases where the noise happens to contain a real signal
    bad_markers = ("missing", "required", "extra", "unexpected",
                   "not permitted", "forbidden", "unknown")
    assume(not any(m in noise.lower() for m in bad_markers))
    _promote_field_signals_into_hints(env)
    assert env["hints"] == []


def test_promote_handles_dirty_paths_via_sanitize() -> None:
    """Anchor: a path with trailing junk gets cleaned before promotion."""
    env = _envelope_with_details([
        {"path": "reportTypes;", "issue": "field required"},
    ])
    _promote_field_signals_into_hints(env)
    # The hint must show the *clean* name, not the trailing semicolon.
    assert "Required field missing: 'reportTypes'." in env["hints"]
    assert "reportTypes;" not in " ".join(env["hints"])
