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
