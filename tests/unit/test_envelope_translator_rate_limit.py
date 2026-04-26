"""Verify the envelope translator auto-extracts rate-limit headers from
httpx HTTP errors and surfaces them in ``_meta``.

This is the wire-up test connecting the rate-limit header parser
(``utils/http/rate_limit_headers.py``) to the envelope translator
(``middleware/error_envelope.py``).
"""

from __future__ import annotations


import httpx


def _make_response(headers: dict[str, str], status_code: int) -> httpx.Response:
    request = httpx.Request("GET", "https://advertising-api.amazon.com/v2/profiles")
    return httpx.Response(status_code, request=request, headers=headers)


# ---------------------------------------------------------------------------
# 429 with Retry-After + X-RateLimit-* surfaces in `_meta`
# ---------------------------------------------------------------------------


def test_429_envelope_includes_retry_after_and_rate_limit_block():
    from amazon_ads_mcp.middleware.error_envelope import (
        build_envelope_from_exception,
    )

    response = _make_response(
        {
            "Retry-After": "30",
            "X-RateLimit-Limit": "10",
            "X-RateLimit-Remaining": "0",
            "X-RateLimit-Reset": "1714074153",
        },
        status_code=429,
    )
    exc = httpx.HTTPStatusError("throttled", request=response.request, response=response)
    envelope = build_envelope_from_exception(exc, tool_name="adsv1_list_campaigns")

    assert envelope["error_kind"] == "rate_limited"
    meta = envelope["_meta"]
    assert meta["retry_after_seconds"] == 30.0
    assert meta["rate_limit"] == {
        "limit_per_second": 10.0,
        "remaining": 0.0,
        "reset_at": "1714074153",
    }


def test_400_envelope_still_carries_rate_limit_headroom_when_present():
    """Even non-rate_limited errors carry headroom telemetry when upstream
    sends it; agents can use the data to slow down before the next call."""
    from amazon_ads_mcp.middleware.error_envelope import (
        build_envelope_from_exception,
    )

    response = _make_response(
        {"X-RateLimit-Limit": "10", "X-RateLimit-Remaining": "2"},
        status_code=400,
    )
    exc = httpx.HTTPStatusError("bad", request=response.request, response=response)
    envelope = build_envelope_from_exception(exc, tool_name="adsv1_list_campaigns")

    assert envelope["error_kind"] == "ads_api_http"
    assert envelope["_meta"]["rate_limit"]["remaining"] == 2.0


def test_500_with_no_rate_limit_headers_has_no_meta():
    """Server-side 5xx with no headers should not include synthetic _meta."""
    from amazon_ads_mcp.middleware.error_envelope import (
        build_envelope_from_exception,
    )

    response = _make_response({}, status_code=500)
    exc = httpx.HTTPStatusError("boom", request=response.request, response=response)
    envelope = build_envelope_from_exception(exc, tool_name="t")

    assert envelope["error_kind"] == "ads_api_http"
    assert "_meta" not in envelope


# ---------------------------------------------------------------------------
# Explicit http_meta still wins over auto-extraction
# ---------------------------------------------------------------------------


def test_explicit_http_meta_overrides_response_headers():
    """When the caller passes ``http_meta`` explicitly, it overrides
    auto-extraction so callers retain control."""
    from amazon_ads_mcp.middleware.error_envelope import (
        build_envelope_from_exception,
    )

    response = _make_response({"Retry-After": "5"}, status_code=429)
    exc = httpx.HTTPStatusError("throttled", request=response.request, response=response)

    envelope = build_envelope_from_exception(
        exc,
        tool_name="t",
        http_meta={"retry_after_seconds": 99.0},
    )
    # Caller's explicit value takes precedence
    assert envelope["_meta"]["retry_after_seconds"] == 99.0
