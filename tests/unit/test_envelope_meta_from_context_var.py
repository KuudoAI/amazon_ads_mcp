"""Round 5 #2: Ads envelope translator must surface ``_meta`` from the
captured per-call context-var, not just from ``httpx.HTTPStatusError``.

Today ``_merge_http_meta`` only auto-extracts rate-limit headers from
the response on an ``httpx.HTTPStatusError``. When the failing path is a
typed exception that doesn't carry a response (e.g.
``AmazonAdsMCPError`` subclasses raised before any HTTP call, or after
the call succeeded but post-processing failed), captured rate-limit
data sits in ``_LAST_HTTP_META`` but never reaches the error envelope.

Fix: consult ``get_last_http_meta()`` as a fallback when neither the
explicit ``http_meta`` arg nor an HTTPStatusError response provides
auto-extracted data.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _reset_http_meta():
    from amazon_ads_mcp.utils.http.rate_limit_headers import clear_last_http_meta

    clear_last_http_meta()
    yield
    clear_last_http_meta()


def test_typed_exception_envelope_picks_up_context_var_meta():
    """A typed exception (no httpx response) raised after upstream sent
    rate-limit headers must still produce an envelope with
    ``_meta.rate_limit`` — read from the per-call context-var that
    ``AuthenticatedClient.send`` populated."""
    from amazon_ads_mcp.exceptions import APIError
    from amazon_ads_mcp.middleware.error_envelope import build_envelope_from_exception
    from amazon_ads_mcp.utils.http.rate_limit_headers import set_last_http_meta

    # Simulate the HTTP client capturing meta before the typed exception fires
    set_last_http_meta(
        {
            "rate_limit": {
                "limit_per_second": 10.0,
                "remaining": 0.0,
                "reset_at": "1714074153",
            },
            "retry_after_seconds": 30.0,
        }
    )

    exc = APIError("Throttled by Amazon", status_code=429)
    envelope = build_envelope_from_exception(exc, tool_name="adsv1_list_campaigns")

    meta = envelope.get("_meta") or {}
    assert meta.get("rate_limit", {}).get("limit_per_second") == 10.0
    assert meta.get("retry_after_seconds") == 30.0


def test_explicit_http_meta_still_overrides_context_var():
    """Explicit caller-supplied ``http_meta`` continues to take
    precedence over the context-var fallback."""
    from amazon_ads_mcp.middleware.error_envelope import build_envelope_from_exception
    from amazon_ads_mcp.utils.http.rate_limit_headers import set_last_http_meta

    set_last_http_meta({"retry_after_seconds": 1.0})

    envelope = build_envelope_from_exception(
        RuntimeError("boom"),
        tool_name="t",
        http_meta={"retry_after_seconds": 99.0},
    )
    assert envelope["_meta"]["retry_after_seconds"] == 99.0


def test_no_context_var_no_explicit_no_response_means_no_meta():
    """When nothing populated the context-var, no HTTPStatusError, no
    explicit http_meta — the envelope has no ``_meta`` block."""
    from amazon_ads_mcp.middleware.error_envelope import build_envelope_from_exception

    envelope = build_envelope_from_exception(RuntimeError("boom"), tool_name="t")
    assert "_meta" not in envelope


def test_http_status_error_response_meta_still_works():
    """Round 3-A behavior unchanged: an httpx.HTTPStatusError with
    rate-limit headers in the response still auto-extracts."""
    import httpx

    from amazon_ads_mcp.middleware.error_envelope import build_envelope_from_exception

    request = httpx.Request("GET", "https://example.com")
    response = httpx.Response(
        429, request=request, headers={"X-RateLimit-Limit": "5", "Retry-After": "10"}
    )
    exc = httpx.HTTPStatusError("throttled", request=request, response=response)
    envelope = build_envelope_from_exception(exc, tool_name="t")
    assert envelope["_meta"]["rate_limit"]["limit_per_second"] == 5.0
    assert envelope["_meta"]["retry_after_seconds"] == 10.0


def test_context_var_supplements_partial_explicit_http_meta():
    """When explicit http_meta is partial (only retry_after, no
    rate_limit) and context-var has the missing pieces, both surface.
    Explicit values still win on key collisions."""
    from amazon_ads_mcp.middleware.error_envelope import build_envelope_from_exception
    from amazon_ads_mcp.utils.http.rate_limit_headers import set_last_http_meta

    set_last_http_meta(
        {"rate_limit": {"limit_per_second": 5.0, "remaining": 1.0}}
    )

    envelope = build_envelope_from_exception(
        RuntimeError("boom"),
        tool_name="t",
        http_meta={"retry_after_seconds": 7.0},
    )
    meta = envelope["_meta"]
    assert meta["retry_after_seconds"] == 7.0
    assert meta["rate_limit"]["limit_per_second"] == 5.0
    assert meta["rate_limit"]["remaining"] == 1.0
