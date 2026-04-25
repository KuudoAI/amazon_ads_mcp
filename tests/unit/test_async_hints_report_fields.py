"""Tests for the AdsApiv1CreateReport async hint gating on report_fields.

Locked contract (adsv1.md §E.5):
- When ENABLE_REPORT_FIELDS_TOOL=true (default), the hint for
  AdsApiv1CreateReport references report_fields(mode="validate", ...) with
  a full example (and still mentions list_report_fields as baseline).
- When ENABLE_REPORT_FIELDS_TOOL=false, the hint does NOT reference
  report_fields — it falls back to the pre-PR guidance pointing only at
  list_report_fields.
"""

from __future__ import annotations



def _get_hint(tool_key: str) -> str:
    from amazon_ads_mcp.server.async_hints_transform import get_hint_text

    return get_hint_text(tool_key)


def _rebuild_settings():
    from amazon_ads_mcp.config import settings as settings_mod

    settings_mod.settings = settings_mod.Settings()


def test_hint_references_report_fields_when_enabled(monkeypatch):
    monkeypatch.delenv("ENABLE_REPORT_FIELDS_TOOL", raising=False)
    _rebuild_settings()

    hint = _get_hint("AdsApiv1CreateReport")
    assert "report_fields" in hint
    # Full example — both modes shown.
    assert 'mode="validate"' in hint or "mode='validate'" in hint
    assert 'mode="query"' in hint or "mode='query'" in hint
    # Still references list_report_fields as baseline for discoverability.
    assert "list_report_fields" in hint


def test_hint_falls_back_when_report_fields_disabled(monkeypatch):
    monkeypatch.setenv("ENABLE_REPORT_FIELDS_TOOL", "false")
    _rebuild_settings()

    try:
        hint = _get_hint("AdsApiv1CreateReport")
    finally:
        monkeypatch.delenv("ENABLE_REPORT_FIELDS_TOOL", raising=False)
        _rebuild_settings()

    # Must NOT direct agents to call report_fields(mode="validate", ...) —
    # the tool isn't registered. Concrete signal: the mode=... syntax is absent.
    assert "mode=" not in hint, (
        "fallback hint must not reference report_fields(mode=...) syntax "
        "when ENABLE_REPORT_FIELDS_TOOL=false"
    )
    # `list_report_fields` (substring) is fine — that tool still registers.
    assert "list_report_fields" in hint


def test_create_report_hint_contains_v1_request_skeleton(monkeypatch):
    """P0.2 — hint must carry a minimal, paste-able v1 CreateReport body.

    Fires in both gating states; the skeleton itself is non-negotiable either way.
    """
    for state, applier in (
        (
            "enabled",
            lambda: monkeypatch.delenv("ENABLE_REPORT_FIELDS_TOOL", raising=False),
        ),
        ("disabled", lambda: monkeypatch.setenv("ENABLE_REPORT_FIELDS_TOOL", "false")),
    ):
        applier()
        _rebuild_settings()
        try:
            hint = _get_hint("AdsApiv1CreateReport")
        finally:
            monkeypatch.delenv("ENABLE_REPORT_FIELDS_TOOL", raising=False)
            _rebuild_settings()
        # v1 top-level shape
        assert "accessRequestedAccounts" in hint, f"{state}: missing accessRequestedAccounts"
        assert "reports" in hint
        # The part every 400-ping-pong case misses: datePeriod nesting under periods[]
        assert "periods" in hint and "datePeriod" in hint
        assert "startDate" in hint and "endDate" in hint
        # CreateComparisonPredicate requires `not` — omitting it 400s.
        assert '"not"' in hint, f"{state}: filter skeleton missing required `not`"
        # v3-shaped keys must NOT leak in (regression guard)
        assert "reportTypeId" not in hint
        assert '"columns"' not in hint
        assert '"configuration"' not in hint
        # ComparisonOperator.enum = ["EQUALS", "IN"] — "EQUAL_TO" is a hallucinated
        # value from an earlier planning draft; it must never appear.
        assert '"EQUAL_TO"' not in hint
        assert '"EQUALS"' in hint


def test_hint_skeleton_validates_against_openapi_create_report_request(monkeypatch):
    """P0.2 — parse the skeleton out of the hint, validate it against the live
    CreateReportRequest schema. This is the backstop against the hint drifting
    when the spec regenerates."""
    import json
    import re

    import jsonschema

    from amazon_ads_mcp.utils.openapi import load_bundled_spec

    monkeypatch.delenv("ENABLE_REPORT_FIELDS_TOOL", raising=False)
    _rebuild_settings()

    hint = _get_hint("AdsApiv1CreateReport")

    # Extract JSON-looking block: first '{' through matching '}' — tolerates the
    # hint being wrapped in prose. The skeleton itself is self-contained JSON.
    start = hint.find("{")
    assert start >= 0, "skeleton JSON block not found in hint"
    # Brace-match from the first '{'
    depth = 0
    end = -1
    in_str = False
    esc = False
    for i in range(start, len(hint)):
        ch = hint[i]
        if esc:
            esc = False
            continue
        if ch == "\\":
            esc = True
            continue
        if ch == '"':
            in_str = not in_str
            continue
        if in_str:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                end = i + 1
                break
    assert end > start, "skeleton JSON block not brace-balanced"
    raw = hint[start:end]
    # Replace angle-bracket placeholders with a realistic string value so the
    # example is schema-valid without leaking placeholder text into production.
    raw = re.sub(r"<[^>]+>", "amzn1.ads-account.g.EXAMPLE", raw)
    example = json.loads(raw)

    spec = load_bundled_spec("AdsAPIv1All")
    schema = spec["components"]["schemas"]["CreateReportRequest"]
    resolver = jsonschema.RefResolver.from_schema(spec)
    jsonschema.validate(example, schema, resolver=resolver)


def test_hint_uses_correct_query_advertiser_account_tool_name(monkeypatch):
    """P0.1 — operationId is `QueryAdvertiserAccount`; the mounted tool name is
    `allv1_QueryAdvertiserAccount` (no `AdsApiv1` segment). An earlier draft of the
    hint text used the non-existent `allv1_AdsApiv1QueryAdvertiserAccount` which
    sent agents on a wild goose chase."""
    # Assert across BOTH gating states — the name must be right regardless of
    # whether report_fields is enabled.
    for state, applier in (
        (
            "enabled",
            lambda: monkeypatch.delenv("ENABLE_REPORT_FIELDS_TOOL", raising=False),
        ),
        ("disabled", lambda: monkeypatch.setenv("ENABLE_REPORT_FIELDS_TOOL", "false")),
    ):
        applier()
        _rebuild_settings()
        try:
            hint = _get_hint("AdsApiv1CreateReport")
        finally:
            monkeypatch.delenv("ENABLE_REPORT_FIELDS_TOOL", raising=False)
            _rebuild_settings()
        assert (
            "allv1_QueryAdvertiserAccount" in hint
        ), f"correct tool name missing in {state} hint"
        assert (
            "allv1_AdsApiv1QueryAdvertiserAccount" not in hint
        ), f"stale tool name still present in {state} hint"


def test_retrieve_report_hint_guides_polling_cadence():
    """P1.4 — PENDING/PROCESSING response needs more than bare status text.
    The client complaint was that a polling agent had to guess whether to
    check back in 60 seconds or 20 minutes. Add a ballpark cadence sentence;
    we are NOT committing to a stateful ETA."""
    hint = _get_hint("AdsApiv1RetrieveReport")
    # Any of these cadence tokens is acceptable — wording may evolve but the
    # concept must appear.
    cadence_tokens = (
        "typical",
        "usually",
        "1-5 minutes",
        "1-20 minutes",
        "60 seconds",
        "30-60s",
        "poll at",
    )
    assert any(tok in hint for tok in cadence_tokens), (
        f"retrieve hint missing polling cadence guidance; got: {hint!r}"
    )
    assert "PENDING" in hint


def test_create_report_hint_flags_served_in_window_limitation(monkeypatch):
    """P1.6 — v1 reports only return campaigns that served in-window, so
    ``deliveryStatus`` from these reports is not a proxy for true state.
    The hint must call this out explicitly."""
    monkeypatch.delenv("ENABLE_REPORT_FIELDS_TOOL", raising=False)
    _rebuild_settings()
    hint = _get_hint("AdsApiv1CreateReport")
    assert "served" in hint.lower()
    # Either the "true state" phrasing or the state enum vocabulary.
    assert "true state" in hint.lower() or "enabled/paused" in hint.lower()


def test_create_report_hint_points_to_campaign_management_category_not_specific_tool(
    monkeypatch,
):
    """P1.6 — reference the generic category, not a specific op ID, so the
    hint degrades gracefully across deployments with different mount configs."""
    monkeypatch.delenv("ENABLE_REPORT_FIELDS_TOOL", raising=False)
    _rebuild_settings()
    hint = _get_hint("AdsApiv1CreateReport")
    lower = hint.lower()
    assert (
        "campaign list" in lower
        or "campaign management" in lower
        or "campaign list/query" in lower
    )


def test_create_report_hint_offers_a_discovery_fallback(monkeypatch):
    """P1.6 — when a tool isn't visible, the hint must name the discovery
    escape hatch so the agent can find the campaign-management surface."""
    monkeypatch.delenv("ENABLE_REPORT_FIELDS_TOOL", raising=False)
    _rebuild_settings()
    hint = _get_hint("AdsApiv1CreateReport")
    # list_tool_groups / enable_tool_group are always-on builtins; search /
    # get_schemas are code-mode meta-tools. At least one must appear.
    assert any(
        tok in hint
        for tok in ("list_tool_groups", "enable_tool_group", "search", "get_schemas")
    )


def test_create_report_hint_does_not_prescribe_a_single_product_line(monkeypatch):
    """P1.6 — regression guard: if we name product lines, they should be
    framed as examples, not a prescription."""
    monkeypatch.delenv("ENABLE_REPORT_FIELDS_TOOL", raising=False)
    _rebuild_settings()
    hint = _get_hint("AdsApiv1CreateReport")
    lower = hint.lower()
    assert any(tok in lower for tok in ("example", "e.g.", "such as"))


def test_other_hints_unaffected_by_report_fields_flag(monkeypatch):
    """Hints unrelated to AdsApiv1CreateReport must not change when the flag toggles."""
    monkeypatch.delenv("ENABLE_REPORT_FIELDS_TOOL", raising=False)
    _rebuild_settings()
    baseline = _get_hint("createAsyncReport")

    monkeypatch.setenv("ENABLE_REPORT_FIELDS_TOOL", "false")
    _rebuild_settings()
    try:
        with_flag = _get_hint("createAsyncReport")
    finally:
        monkeypatch.delenv("ENABLE_REPORT_FIELDS_TOOL", raising=False)
        _rebuild_settings()

    assert baseline == with_flag
