"""Round 13 Phase C-2 — operator-misuse detection on validate_body.

When `validate_body` walks the request body, it inspects filter
shapes for known-bad operators (BETWEEN, LIKE, NOT_IN) and surfaces
each in `operator_misuse[]` with a curated replacement hint. The
schema only allows `EQUALS` and `IN` per the live spec, but agents
reflexively reach for SQL-style operators.

Pinned contract:
  - `OPERATOR_MISUSE` table is exposed at module scope so tests
    pin coverage of known-bad operators.
  - Each entry carries (message, replacement_operators).
  - `validate_body` walks all filter shapes (top-level filters,
    reports[*].query.filter, etc.) and emits one entry per misuse.
  - BETWEEN-on-filter specifically points the agent at
    `periods[].datePeriod` for date ranges (the v1-correct path).
"""

from __future__ import annotations


from amazon_ads_mcp.tools.report_fields_v1_handler import (
    OPERATOR_MISUSE,
    handle as report_fields_handle,
)


# ---- Table shape pin -----------------------------------------------------


def test_operator_misuse_table_covers_known_reflexes() -> None:
    """The three SQL/v3-reflex operators that don't exist in v1 MUST
    be in the table. Adding more is fine; missing any is a regression."""
    required = {"BETWEEN", "LIKE", "NOT_IN"}
    missing = required - set(OPERATOR_MISUSE.keys())
    assert not missing


def test_operator_misuse_entries_have_message_and_replacements() -> None:
    for op, entry in OPERATOR_MISUSE.items():
        assert isinstance(entry, tuple) and len(entry) == 2
        message, replacements = entry
        assert isinstance(message, str) and message
        assert isinstance(replacements, list) and replacements
        for r in replacements:
            assert isinstance(r, str) and r


def test_between_misuse_message_redirects_date_ranges() -> None:
    message, replacements = OPERATOR_MISUSE["BETWEEN"]
    msg_lower = message.lower()
    # The fix the client report flagged: BETWEEN doesn't exist on
    # filters; date ranges go in `periods[].datePeriod`.
    assert "periods" in msg_lower or "dateperiod" in msg_lower, (
        f"BETWEEN misuse hint must redirect to periods[].datePeriod; "
        f"got: {message}"
    )
    assert "EQUALS" in replacements or "IN" in replacements


# ---- validate_body integration ------------------------------------------


def _body_with_between_filter() -> dict:
    """Body shape with BETWEEN on a filter — the exact v3-reflex
    pattern the client report described."""
    return {
        "accessRequestedAccounts": [
            {"advertiserAccountId": "amzn1.ads-account.g.placeholder"}
        ],
        "reports": [
            {
                "format": "GZIP_JSON",
                "periods": [
                    {
                        "datePeriod": {
                            "startDate": "2026-04-01",
                            "endDate": "2026-04-07",
                        }
                    }
                ],
                "query": {
                    "fields": ["metric.totalCost", "campaign.id"],
                    "filter": {
                        "field": "date.value",
                        "operator": "BETWEEN",
                        "values": ["2026-04-01", "2026-04-07"],
                    },
                },
            }
        ],
    }


def test_validate_body_flags_between_operator_misuse() -> None:
    """Client finding 2 / Phase C-2: BETWEEN on a filter is a
    natural-language reflex; schema only accepts EQUALS / IN.
    validate_body must surface this in operator_misuse[]."""
    result = report_fields_handle(
        mode="validate_body",
        operation="allv1_AdsApiv1CreateReport",
        body=_body_with_between_filter(),
    )
    payload = result.model_dump(exclude_none=True)
    misuses = payload.get("operator_misuse") or []
    assert misuses, "validate_body must surface BETWEEN as operator_misuse"
    found = next(
        (m for m in misuses if m.get("operator") == "BETWEEN"), None
    )
    assert found, f"BETWEEN entry missing from operator_misuse: {misuses}"
    msg = (found.get("message") or "").lower()
    assert "periods" in msg or "dateperiod" in msg, (
        f"BETWEEN misuse must redirect to periods[].datePeriod; got {found}"
    )
    replacements = found.get("replacement") or []
    assert "EQUALS" in replacements or "IN" in replacements


def test_validate_body_no_misuse_when_filter_uses_canonical_operator() -> None:
    """Filter with EQUALS or IN should NOT trigger operator_misuse."""
    body = _body_with_between_filter()
    body["reports"][0]["query"]["filter"]["operator"] = "EQUALS"
    result = report_fields_handle(
        mode="validate_body",
        operation="allv1_AdsApiv1CreateReport",
        body=body,
    )
    payload = result.model_dump(exclude_none=True)
    assert (payload.get("operator_misuse") or []) == []


def test_validate_body_flags_like_operator_misuse() -> None:
    body = _body_with_between_filter()
    body["reports"][0]["query"]["filter"]["operator"] = "LIKE"
    result = report_fields_handle(
        mode="validate_body",
        operation="allv1_AdsApiv1CreateReport",
        body=body,
    )
    payload = result.model_dump(exclude_none=True)
    misuses = payload.get("operator_misuse") or []
    assert any(m.get("operator") == "LIKE" for m in misuses)


def test_validate_body_flags_not_in_operator_misuse() -> None:
    body = _body_with_between_filter()
    body["reports"][0]["query"]["filter"]["operator"] = "NOT_IN"
    result = report_fields_handle(
        mode="validate_body",
        operation="allv1_AdsApiv1CreateReport",
        body=body,
    )
    payload = result.model_dump(exclude_none=True)
    misuses = payload.get("operator_misuse") or []
    assert any(m.get("operator") == "NOT_IN" for m in misuses)
