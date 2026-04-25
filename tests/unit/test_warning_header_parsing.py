"""Phase 4: parse upstream HTTP ``Warning`` headers into ``_meta.warnings[]``.

Per RFC 7234 the ``Warning`` header carries informational notes about the
response (e.g. ``199 - "stale response served"``, ``214 - "Transformation
applied"``). The v1 envelope contract surfaces these under
``_meta.warnings[]`` with the same shape as error envelopes:
``{kind, summary, details, hints}``. Default ``kind`` for upstream-emitted
warnings is ``upstream_warning`` — Phase 4 per-server appendices add
domain-specific kinds (``cached_or_stale_data``, ``profile_scope_warning``,
etc.) layered on top.
"""

from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest


def _make_response(headers: dict[str, str], status_code: int = 200) -> httpx.Response:
    request = httpx.Request("GET", "https://advertising-api.amazon.com/v2/profiles")
    return httpx.Response(status_code, request=request, headers=headers)


# ---------------------------------------------------------------------------
# Single Warning header
# ---------------------------------------------------------------------------


def test_single_warning_header_surfaces_as_upstream_warning():
    from amazon_ads_mcp.utils.http.rate_limit_headers import extract_rate_limit_meta

    resp = _make_response({"Warning": '199 - "stale response served"'})
    meta = extract_rate_limit_meta(resp)
    assert meta["warnings"] == [
        {
            "kind": "upstream_warning",
            "summary": '199 - "stale response served"',
            "details": [],
            "hints": [],
        }
    ]


def test_warning_header_alongside_rate_limit_in_same_response():
    from amazon_ads_mcp.utils.http.rate_limit_headers import extract_rate_limit_meta

    resp = _make_response(
        {
            "Warning": '214 - "Transformation applied"',
            "X-RateLimit-Limit": "10",
        }
    )
    meta = extract_rate_limit_meta(resp)
    assert meta["rate_limit"]["limit_per_second"] == 10.0
    assert meta["warnings"][0]["kind"] == "upstream_warning"


# ---------------------------------------------------------------------------
# Empty / absent
# ---------------------------------------------------------------------------


def test_no_warning_header_means_no_warnings_key():
    from amazon_ads_mcp.utils.http.rate_limit_headers import extract_rate_limit_meta

    resp = _make_response({})
    meta = extract_rate_limit_meta(resp)
    assert "warnings" not in meta


def test_empty_warning_header_value_is_ignored():
    from amazon_ads_mcp.utils.http.rate_limit_headers import extract_rate_limit_meta

    resp = _make_response({"Warning": "   "})
    meta = extract_rate_limit_meta(resp)
    assert "warnings" not in meta


# ---------------------------------------------------------------------------
# Middleware injects _meta.warnings on success
# ---------------------------------------------------------------------------


def _make_context() -> SimpleNamespace:
    message = SimpleNamespace(name="t", arguments={})
    return SimpleNamespace(message=message, fastmcp_context=None)


@pytest.mark.asyncio
async def test_meta_injection_middleware_surfaces_warnings_on_success():
    from amazon_ads_mcp.middleware.meta_injection_middleware import (
        MetaInjectionMiddleware,
    )
    from amazon_ads_mcp.utils.http.rate_limit_headers import set_last_http_meta

    middleware = MetaInjectionMiddleware()

    async def call_next(_ctx):
        set_last_http_meta(
            {
                "warnings": [
                    {
                        "kind": "upstream_warning",
                        "summary": "stale response",
                        "details": [],
                        "hints": [],
                    }
                ]
            }
        )
        return {"data": "ok"}

    result = await middleware.on_call_tool(_make_context(), call_next)
    assert result["_meta"]["warnings"][0]["summary"] == "stale response"
