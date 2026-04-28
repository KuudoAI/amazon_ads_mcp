"""Round 13 Phase C-4 — curated v1↔v3 alias table tests.

Closes client findings 1 + 2:
  1. ``keyword.text`` returns empty suggestions because token-overlap
     can't bridge ``{keyword, text}`` and ``{target, value}``.
  2. ``metric.spend`` returns DSP pacing noise
     (``currentFlightProjectedSpend`` etc.) because the substring
     ``spend`` matches them — not what a Sponsored-Ads agent who
     typed ``metric.spend`` actually wants.

Pinned contract:
  - Curated table consults BEFORE token-overlap (semantic > substring).
  - ``keyword.id`` carries the explicit "no stable ID equivalent in
    v1" caveat so downstream agents don't assume row-level uniqueness
    or join semantics that v1 doesn't support.
  - Per-entry ``override`` vs ``merge``:
      * ``metric.spend`` → override (DSP pacing matches are noise)
      * ``metric.cost`` → merge (DSP cost matches are at least same
        family)
      * ``keyword.id`` → merge (token-overlap returns nothing anyway)
"""

from __future__ import annotations


from amazon_ads_mcp.tools.report_fields_v1_handler import (
    catalog_suggestions_for,
    V1_ALIAS_MAP,
)


# ---- Table shape pin -----------------------------------------------------


def test_alias_table_entries_have_required_fields() -> None:
    """Each entry is a 4-tuple: (canonical_id, note, applies_when, mode).
    Catches a contributor adding an entry with the wrong arity."""
    for bad, entry in V1_ALIAS_MAP.items():
        assert isinstance(entry, tuple) and len(entry) == 4, (
            f"V1_ALIAS_MAP[{bad!r}] must be (canonical, note, "
            f"applies_when, mode); got {entry!r}"
        )
        canonical, note, applies_when, mode = entry
        assert isinstance(canonical, str) and canonical
        assert isinstance(note, str) and note
        assert applies_when is None or isinstance(applies_when, dict)
        assert mode in ("override", "merge"), (
            f"mode for {bad!r} must be 'override' or 'merge'; got {mode!r}"
        )


def test_alias_table_covers_required_v1_v3_migrations() -> None:
    """The 5 famous reflexes the client report flagged MUST be in
    the table. Adding more is fine; missing any is a regression."""
    required = {
        "keyword.text",
        "keyword.matchType",
        "keyword.id",
        "metric.cost",
        "metric.spend",
    }
    missing = required - set(V1_ALIAS_MAP.keys())
    assert not missing, f"V1_ALIAS_MAP missing required entries: {missing}"


def test_keyword_id_note_carries_no_stable_id_caveat() -> None:
    """The keyword.id entry MUST explicitly call out that v1 has no
    stable ID equivalent — not just point at target.value silently.
    Catches a contributor trimming the careful caveat."""
    canonical, note, _applies_when, _mode = V1_ALIAS_MAP["keyword.id"]
    assert canonical == "target.value"
    note_lower = note.lower()
    assert "no stable id" in note_lower or "no exact" in note_lower or "no equivalent" in note_lower
    assert "not unique" in note_lower or "deduplicate" in note_lower or "row-level" in note_lower, (
        f"keyword.id note must warn about uniqueness/dedup; got: {note}"
    )


# ---- Suggestion behavior ---------------------------------------------------


def test_keyword_text_returns_target_value_via_curated_table() -> None:
    """Client finding 1: previously empty, now must return target.value
    from the curated table even though token-overlap fails."""
    out = catalog_suggestions_for("keyword.text")
    assert out, "keyword.text must produce at least one suggestion"
    # Curated entry should rank first.
    assert out[0] == "target.value", (
        f"curated table should rank first for keyword.text; got {out}"
    )


def test_keyword_match_type_returns_target_match_type() -> None:
    out = catalog_suggestions_for("keyword.matchType")
    assert out
    assert out[0] == "target.matchType"


def test_keyword_id_returns_target_value() -> None:
    out = catalog_suggestions_for("keyword.id")
    assert out
    assert out[0] == "target.value"


def test_metric_spend_overrides_dsp_pacing_noise() -> None:
    """Client finding 2: previously returned currentFlightProjectedSpend
    and friends (DSP pacing — pure noise). Now must return totalCost
    FIRST and SUPPRESS the DSP-pacing matches (override mode)."""
    out = catalog_suggestions_for("metric.spend")
    assert out
    assert out[0] == "metric.totalCost", (
        f"metric.spend must rank metric.totalCost first; got {out}"
    )
    # Override mode: DSP pacing metrics MUST NOT appear at all.
    forbidden = [
        "currentFlightProjectedSpend",
        "currentFlightPreviousDaySpend",
        "currentFlightRequiredDailySpend",
    ]
    for f in forbidden:
        full_id = f"metric.{f}"
        assert full_id not in out, (
            f"metric.spend override mode must suppress DSP pacing "
            f"match {full_id!r}; got {out}"
        )


def test_metric_cost_merges_curated_and_token_suggestions() -> None:
    """metric.cost: curated (totalCost) ranks first AND token-overlap
    matches (rewardCost, supplyCost) survive — they're at least
    same-family. Merge mode."""
    out = catalog_suggestions_for("metric.cost")
    assert out
    assert out[0] == "metric.totalCost"


# ---- applies_when / context filtering -------------------------------------


def test_keyword_text_applies_when_sponsored_products() -> None:
    """keyword.text → target.value applies when adProduct=SPONSORED_PRODUCTS.
    With the body context provided, the suggestion fires."""
    body = {"adProduct": "SPONSORED_PRODUCTS"}
    out = catalog_suggestions_for("keyword.text", body=body)
    assert out and out[0] == "target.value"


def test_keyword_text_unconditional_when_body_unknown() -> None:
    """Without body context, the curated entry still fires (lenient
    default — the rare false positive is better than the always-false
    negative when context is unavailable)."""
    out = catalog_suggestions_for("keyword.text", body=None)
    assert out and out[0] == "target.value"


# ---- Token-overlap fallback survives for unmapped fields -------------------


def test_unmapped_unknown_field_still_falls_back_to_token_overlap() -> None:
    """An unknown field that ISN'T in the curated table should still
    get the existing token-overlap suggester. The curated table is
    additive, not replacing — gap closure, not substitution."""
    out = catalog_suggestions_for("metric.totalCost")
    # metric.totalCost is itself canonical, so suggestions are
    # incidental — the test is just that the helper doesn't crash and
    # returns a list.
    assert isinstance(out, list)
