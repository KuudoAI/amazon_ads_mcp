"""Date-range pre-flight for ``report_fields(mode="validate")``.

Exercises the time-window check wired onto validate mode: a requested
``start_date``/``end_date`` is checked against the selected time grain's
``max_report_pull`` span cap and ``historical_data`` lookback (adsv1
reporting time-periods guide).

These run against the REAL packaged catalog (so grains like ``date.value``
resolve as known fields) with a pinned ``_today`` for deterministic verdicts.
"""

from __future__ import annotations

from datetime import date

import pytest

from amazon_ads_mcp.tools import report_fields_v1_handler as h
from amazon_ads_mcp.tools.report_fields_v1_handler import (
    ReportFieldsToolError,
    _subtract_months,
    _window_floor,
    handle,
)

_FIXED_TODAY = date(2026, 6, 10)


@pytest.fixture(autouse=True)
def _pin_today(monkeypatch):
    monkeypatch.setattr(h, "_today", lambda: _FIXED_TODAY)


# ---------------------------------------------------------------------------
# calendar month arithmetic
# ---------------------------------------------------------------------------


def test_subtract_months_clamps_short_month():
    # Feb 2026 has 28 days → Mar 31 minus one month clamps to Feb 28.
    assert _subtract_months(date(2026, 3, 31), 1) == date(2026, 2, 28)


def test_subtract_months_crosses_year_boundary():
    assert _subtract_months(date(2026, 1, 15), 1) == date(2025, 12, 15)
    assert _subtract_months(date(2026, 6, 10), 72) == date(2020, 6, 10)


def test_window_floor_units():
    ref = date(2026, 6, 10)
    assert _window_floor(ref, "120 days") == date(2026, 2, 10)
    assert _window_floor(ref, "15 months") == date(2025, 3, 10)
    # Unrecognized spec → None (caller fails open).
    assert _window_floor(ref, "a fortnight") is None


# ---------------------------------------------------------------------------
# happy path + window verdicts
# ---------------------------------------------------------------------------


def test_window_within_limits_is_valid():
    r = handle(
        mode="validate",
        validate_fields=["date.value"],
        start_date="2026-05-01",
        end_date="2026-05-31",
    )
    assert r.time_window is not None
    tw = r.time_window
    assert tw.grain == "date.value"
    assert tw.within_max_report_pull is True
    assert tw.within_historical_data is True
    assert tw.problems == []
    assert tw.requested_span_days == 30
    assert r.valid is True


def test_window_exceeds_max_pull_only():
    # date.value: 120-day pull, 15-month lookback. 160-day span busts the
    # pull cap but stays inside the lookback.
    r = handle(
        mode="validate",
        validate_fields=["date.value"],
        start_date="2026-01-01",
        end_date="2026-06-10",
    )
    tw = r.time_window
    assert tw.within_max_report_pull is False
    assert tw.within_historical_data is True
    assert any("max report pull" in p for p in tw.problems)
    # Binding floor is the pull floor (end − 120 days), later than the
    # 15-month historical floor.
    assert tw.earliest_allowed_start == "2026-02-10"
    assert r.valid is False


def test_window_exceeds_historical_only():
    # A narrow 31-day span (within the 120-day pull) but starting >15
    # months ago busts only the historical lookback.
    r = handle(
        mode="validate",
        validate_fields=["date.value"],
        start_date="2024-01-01",
        end_date="2024-02-01",
    )
    tw = r.time_window
    assert tw.within_max_report_pull is True
    assert tw.within_historical_data is False
    assert any("historical data" in p for p in tw.problems)
    assert r.valid is False


def test_hour_grain_tight_window():
    # hour.value caps at a 14-day pull AND 14-day lookback.
    r = handle(
        mode="validate",
        validate_fields=["hour.value"],
        start_date="2026-04-01",
        end_date="2026-06-10",
    )
    tw = r.time_window
    assert tw.max_report_pull == "14 days"
    assert tw.within_max_report_pull is False
    assert tw.within_historical_data is False
    assert r.valid is False


def test_month_grain_uses_calendar_month_pull():
    # month.value: 25-month pull. A range starting 29 months before end
    # busts the (calendar-month) pull cap.
    r = handle(
        mode="validate",
        validate_fields=["month.value"],
        start_date="2024-01-01",
        end_date="2026-06-01",
    )
    tw = r.time_window
    assert tw.max_report_pull == "25 months"
    assert tw.within_max_report_pull is False
    # 25 calendar months before 2026-06-01 is 2024-05-01.
    assert tw.earliest_allowed_start >= "2024-05-01"


def test_future_end_date_flagged():
    r = handle(
        mode="validate",
        validate_fields=["date.value"],
        start_date="2026-06-01",
        end_date="2026-12-01",
    )
    tw = r.time_window
    assert any("future" in p for p in tw.problems)
    assert r.valid is False


# ---------------------------------------------------------------------------
# no-op + usage errors
# ---------------------------------------------------------------------------


def test_no_dates_leaves_time_window_none():
    r = handle(mode="validate", validate_fields=["date.value"])
    assert r.time_window is None
    assert r.valid is True


def test_one_date_only_raises():
    with pytest.raises(ReportFieldsToolError) as exc:
        handle(
            mode="validate",
            validate_fields=["date.value"],
            start_date="2026-05-01",
        )
    assert "both be provided" in str(exc.value)


def test_dates_without_time_grain_raises():
    with pytest.raises(ReportFieldsToolError) as exc:
        handle(
            mode="validate",
            validate_fields=["campaign.id"],
            start_date="2026-05-01",
            end_date="2026-05-31",
        )
    assert "time grain" in str(exc.value)


def test_multiple_time_grains_raises():
    with pytest.raises(ReportFieldsToolError) as exc:
        handle(
            mode="validate",
            validate_fields=["date.value", "hour.value"],
            start_date="2026-05-01",
            end_date="2026-05-31",
        )
    assert "one time grain" in str(exc.value)


def test_end_before_start_raises():
    with pytest.raises(ReportFieldsToolError) as exc:
        handle(
            mode="validate",
            validate_fields=["date.value"],
            start_date="2026-05-31",
            end_date="2026-05-01",
        )
    assert "on or after" in str(exc.value)


def test_unparseable_date_raises():
    with pytest.raises(ReportFieldsToolError) as exc:
        handle(
            mode="validate",
            validate_fields=["date.value"],
            start_date="last tuesday",
            end_date="2026-05-31",
        )
    assert "ISO date" in str(exc.value)


def test_window_args_rejected_in_query_mode():
    with pytest.raises(ReportFieldsToolError) as exc:
        handle(mode="query", category="time", start_date="2026-05-01")
    assert "mode='validate' only" in str(exc.value)


# ---------------------------------------------------------------------------
# date_range_preset pre-flight
# ---------------------------------------------------------------------------


def test_preset_supported_is_valid():
    r = handle(
        mode="validate",
        validate_fields=["date.value"],
        date_range_preset="Last 90 days",
    )
    assert r.preset is not None
    assert r.preset.grain == "date.value"
    assert r.preset.supported is True
    assert "Last 90 days" in r.preset.supported_presets
    assert r.valid is True


def test_preset_unsupported_for_narrow_grain():
    # hour.value supports only short presets — "Last 90 days" is not one.
    r = handle(
        mode="validate",
        validate_fields=["hour.value"],
        date_range_preset="Last 90 days",
    )
    assert r.preset.supported is False
    assert r.preset.supported_presets == [
        "Today",
        "Yesterday",
        "Last 7 days",
        "This week",
        "Last week",
    ]
    assert r.valid is False


def test_preset_match_is_case_insensitive():
    r = handle(
        mode="validate",
        validate_fields=["hour.value"],
        date_range_preset="last 7 DAYS",
    )
    assert r.preset.supported is True
    # Caller's input is echoed verbatim; canonical list is unchanged.
    assert r.preset.date_range_preset == "last 7 DAYS"
    assert r.valid is True


def test_no_preset_leaves_preset_none():
    r = handle(mode="validate", validate_fields=["date.value"])
    assert r.preset is None


def test_preset_without_time_grain_raises():
    with pytest.raises(ReportFieldsToolError) as exc:
        handle(
            mode="validate",
            validate_fields=["campaign.id"],
            date_range_preset="Last 30 days",
        )
    assert "time grain" in str(exc.value)


def test_preset_with_multiple_grains_raises():
    with pytest.raises(ReportFieldsToolError) as exc:
        handle(
            mode="validate",
            validate_fields=["date.value", "month.value"],
            date_range_preset="Last 30 days",
        )
    assert "one time grain" in str(exc.value)


def test_preset_rejected_in_query_mode():
    with pytest.raises(ReportFieldsToolError) as exc:
        handle(mode="query", category="time", date_range_preset="Today")
    assert "mode='validate' only" in str(exc.value)


def test_preset_and_window_checks_compose():
    # Both pre-flights run together against the same single grain.
    r = handle(
        mode="validate",
        validate_fields=["date.value"],
        start_date="2026-05-01",
        end_date="2026-05-31",
        date_range_preset="This quarter",
    )
    assert r.time_window is not None and r.time_window.problems == []
    assert r.preset is not None and r.preset.supported is True
    assert r.valid is True
