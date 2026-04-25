"""Unit tests for Amazon Ads rate-limit header parsing.

The helper at ``amazon_ads_mcp.utils.http.rate_limit_headers`` extracts the
``X-RateLimit-*`` family and ``Retry-After`` headers from upstream Amazon
Ads API responses and returns them in the v1 contract shape:

::

    {
      "rate_limit": {"limit_per_second": float|str, "remaining": float|str,
                     "reset_at": str},
      "retry_after_seconds": float
    }

Per the contract, the helper emits **only** the values it could parse —
absent headers result in absent keys, never synthetic ``None`` values.

Header name reference (Amazon Ads API):
- ``X-RateLimit-Limit`` — requests per second allowed for this token
- ``X-RateLimit-Remaining`` — requests remaining in the current window
- ``X-RateLimit-Reset`` — epoch seconds (or ISO timestamp) when the
  bucket resets
- ``Retry-After`` — RFC 7231 seconds OR HTTP-date format
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx


# ---------------------------------------------------------------------------
# Module surface
# ---------------------------------------------------------------------------


def test_module_exposes_extract_rate_limit_meta():
    from amazon_ads_mcp.utils.http import rate_limit_headers as mod

    assert hasattr(mod, "extract_rate_limit_meta")


# ---------------------------------------------------------------------------
# X-RateLimit-* parsing
# ---------------------------------------------------------------------------


def _make_response(headers: dict[str, str], status_code: int = 200) -> httpx.Response:
    request = httpx.Request("GET", "https://advertising-api.amazon.com/v2/profiles")
    return httpx.Response(status_code, request=request, headers=headers)


def test_x_ratelimit_limit_parsed_to_float():
    from amazon_ads_mcp.utils.http.rate_limit_headers import extract_rate_limit_meta

    resp = _make_response({"X-RateLimit-Limit": "5.0"})
    meta = extract_rate_limit_meta(resp)
    assert meta["rate_limit"]["limit_per_second"] == 5.0


def test_x_ratelimit_remaining_parsed_to_float():
    from amazon_ads_mcp.utils.http.rate_limit_headers import extract_rate_limit_meta

    resp = _make_response({"X-RateLimit-Remaining": "12"})
    meta = extract_rate_limit_meta(resp)
    assert meta["rate_limit"]["remaining"] == 12.0


def test_x_ratelimit_reset_passed_through_as_string():
    """Reset header is opaque (sometimes epoch, sometimes ISO); contract
    says servers pass through whatever upstream sends."""
    from amazon_ads_mcp.utils.http.rate_limit_headers import extract_rate_limit_meta

    resp = _make_response({"X-RateLimit-Reset": "1714074153"})
    meta = extract_rate_limit_meta(resp)
    assert meta["rate_limit"]["reset_at"] == "1714074153"


def test_non_numeric_limit_kept_as_string():
    from amazon_ads_mcp.utils.http.rate_limit_headers import extract_rate_limit_meta

    resp = _make_response({"X-RateLimit-Limit": "burst"})
    meta = extract_rate_limit_meta(resp)
    assert meta["rate_limit"]["limit_per_second"] == "burst"


def test_all_three_headers_combined():
    from amazon_ads_mcp.utils.http.rate_limit_headers import extract_rate_limit_meta

    resp = _make_response(
        {
            "X-RateLimit-Limit": "10",
            "X-RateLimit-Remaining": "3",
            "X-RateLimit-Reset": "1714074153",
        }
    )
    meta = extract_rate_limit_meta(resp)
    assert meta["rate_limit"] == {
        "limit_per_second": 10.0,
        "remaining": 3.0,
        "reset_at": "1714074153",
    }


def test_lowercase_headers_also_parsed():
    """httpx normalizes headers to lower-case lookup; verify the helper
    works regardless of case sent by upstream."""
    from amazon_ads_mcp.utils.http.rate_limit_headers import extract_rate_limit_meta

    resp = _make_response({"x-ratelimit-limit": "7"})
    meta = extract_rate_limit_meta(resp)
    assert meta["rate_limit"]["limit_per_second"] == 7.0


# ---------------------------------------------------------------------------
# Retry-After parsing
# ---------------------------------------------------------------------------


def test_retry_after_seconds_parsed_to_float():
    from amazon_ads_mcp.utils.http.rate_limit_headers import extract_rate_limit_meta

    resp = _make_response({"Retry-After": "30"})
    meta = extract_rate_limit_meta(resp)
    assert meta["retry_after_seconds"] == 30.0


def test_retry_after_http_date_parsed_to_seconds_remaining():
    from amazon_ads_mcp.utils.http.rate_limit_headers import extract_rate_limit_meta

    future = datetime.now(timezone.utc) + timedelta(seconds=45)
    http_date = future.strftime("%a, %d %b %Y %H:%M:%S GMT")
    resp = _make_response({"Retry-After": http_date})
    meta = extract_rate_limit_meta(resp)
    # Allow ±2 seconds drift for clock skew during test execution
    assert 43 <= meta["retry_after_seconds"] <= 47


def test_invalid_retry_after_omitted():
    from amazon_ads_mcp.utils.http.rate_limit_headers import extract_rate_limit_meta

    resp = _make_response({"Retry-After": "garbage-not-a-date"})
    meta = extract_rate_limit_meta(resp)
    # Contract: do not emit synthetic values when parsing fails
    assert "retry_after_seconds" not in meta


def test_negative_or_past_retry_after_clamped_to_zero():
    """Past HTTP-date should clamp to 0, not produce a negative value."""
    from amazon_ads_mcp.utils.http.rate_limit_headers import extract_rate_limit_meta

    past = datetime.now(timezone.utc) - timedelta(hours=1)
    http_date = past.strftime("%a, %d %b %Y %H:%M:%S GMT")
    resp = _make_response({"Retry-After": http_date})
    meta = extract_rate_limit_meta(resp)
    assert meta["retry_after_seconds"] == 0.0


# ---------------------------------------------------------------------------
# Empty / absent semantics — contract requires absent keys, not None
# ---------------------------------------------------------------------------


def test_no_rate_limit_headers_returns_empty_dict():
    from amazon_ads_mcp.utils.http.rate_limit_headers import extract_rate_limit_meta

    resp = _make_response({})
    meta = extract_rate_limit_meta(resp)
    assert meta == {}


def test_empty_rate_limit_block_omitted():
    """If only ``Retry-After`` is set, ``rate_limit`` block must be absent
    (not an empty dict)."""
    from amazon_ads_mcp.utils.http.rate_limit_headers import extract_rate_limit_meta

    resp = _make_response({"Retry-After": "10"})
    meta = extract_rate_limit_meta(resp)
    assert "rate_limit" not in meta
    assert meta["retry_after_seconds"] == 10.0


def test_partial_rate_limit_emits_only_present_subkeys():
    """If only X-RateLimit-Limit is set, ``rate_limit`` has just
    ``limit_per_second`` — no synthetic null for remaining/reset_at."""
    from amazon_ads_mcp.utils.http.rate_limit_headers import extract_rate_limit_meta

    resp = _make_response({"X-RateLimit-Limit": "10"})
    meta = extract_rate_limit_meta(resp)
    assert meta["rate_limit"] == {"limit_per_second": 10.0}
    assert "remaining" not in meta["rate_limit"]
    assert "reset_at" not in meta["rate_limit"]


# ---------------------------------------------------------------------------
# Empty/whitespace values treated as absent
# ---------------------------------------------------------------------------


def test_empty_string_header_value_treated_as_absent():
    from amazon_ads_mcp.utils.http.rate_limit_headers import extract_rate_limit_meta

    resp = _make_response({"X-RateLimit-Limit": ""})
    meta = extract_rate_limit_meta(resp)
    assert meta == {}


def test_whitespace_header_value_treated_as_absent():
    from amazon_ads_mcp.utils.http.rate_limit_headers import extract_rate_limit_meta

    resp = _make_response({"X-RateLimit-Limit": "   "})
    meta = extract_rate_limit_meta(resp)
    assert meta == {}
