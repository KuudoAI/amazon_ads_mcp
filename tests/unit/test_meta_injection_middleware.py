"""Unit tests for the success-path ``_meta`` injection middleware.

When upstream Amazon Ads API responses include rate-limit headers, the
HTTP client captures them in a context-var. This middleware reads the
context-var after the tool call succeeds and merges
``_meta.rate_limit`` / ``_meta.retry_after_seconds`` into dict-shaped
responses.

Behavior contract:

- Successful dict responses get ``_meta.rate_limit`` populated **only when**
  rate-limit headers were captured during the call.
- Non-dict responses (lists, strings, primitives, None) pass through unchanged.
- Dict responses without captured meta pass through unchanged.
- The middleware always clears the context-var at the start of a call.
- Pre-existing ``_meta`` keys on the response are preserved; rate-limit data
  is merged additively under ``_meta.rate_limit``.
- Errors raised by ``call_next`` propagate unchanged (envelope middleware
  handles them upstream).
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest


def _make_context() -> SimpleNamespace:
    message = SimpleNamespace(name="t", arguments={})
    return SimpleNamespace(message=message, fastmcp_context=None)


# ---------------------------------------------------------------------------
# Module surface
# ---------------------------------------------------------------------------


def test_module_exposes_meta_injection_middleware():
    from amazon_ads_mcp.middleware import meta_injection_middleware as mod

    assert hasattr(mod, "MetaInjectionMiddleware")


# ---------------------------------------------------------------------------
# Success-path injection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dict_response_gets_meta_rate_limit_when_headers_were_captured():
    from amazon_ads_mcp.middleware.meta_injection_middleware import (
        MetaInjectionMiddleware,
    )
    from amazon_ads_mcp.utils.http.rate_limit_headers import set_last_http_meta

    middleware = MetaInjectionMiddleware()

    async def call_next(_ctx):
        # Simulate the HTTP client populating meta during the call
        set_last_http_meta(
            {"rate_limit": {"limit_per_second": 5.0, "remaining": 2.0, "reset_at": "1714074153"}}
        )
        return {"campaigns": [{"id": "1"}]}

    result = await middleware.on_call_tool(_make_context(), call_next)
    assert result["campaigns"] == [{"id": "1"}]
    assert result["_meta"]["rate_limit"]["limit_per_second"] == 5.0


@pytest.mark.asyncio
async def test_dict_response_with_retry_after_only_gets_retry_after():
    from amazon_ads_mcp.middleware.meta_injection_middleware import (
        MetaInjectionMiddleware,
    )
    from amazon_ads_mcp.utils.http.rate_limit_headers import set_last_http_meta

    middleware = MetaInjectionMiddleware()

    async def call_next(_ctx):
        set_last_http_meta({"retry_after_seconds": 10.0})
        return {"data": "ok"}

    result = await middleware.on_call_tool(_make_context(), call_next)
    assert result["_meta"]["retry_after_seconds"] == 10.0
    assert "rate_limit" not in result["_meta"]


# ---------------------------------------------------------------------------
# No-op cases
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_no_captured_meta_means_no_meta_added():
    from amazon_ads_mcp.middleware.meta_injection_middleware import (
        MetaInjectionMiddleware,
    )

    middleware = MetaInjectionMiddleware()

    async def call_next(_ctx):
        return {"data": "ok"}

    result = await middleware.on_call_tool(_make_context(), call_next)
    assert result == {"data": "ok"}
    assert "_meta" not in result


@pytest.mark.asyncio
async def test_non_dict_response_passes_through_untouched():
    from amazon_ads_mcp.middleware.meta_injection_middleware import (
        MetaInjectionMiddleware,
    )
    from amazon_ads_mcp.utils.http.rate_limit_headers import set_last_http_meta

    middleware = MetaInjectionMiddleware()

    async def call_next(_ctx):
        set_last_http_meta({"rate_limit": {"limit_per_second": 5.0}})
        return ["a", "b", "c"]  # non-dict — middleware must not mutate

    result = await middleware.on_call_tool(_make_context(), call_next)
    assert result == ["a", "b", "c"]


@pytest.mark.asyncio
async def test_none_response_passes_through_untouched():
    from amazon_ads_mcp.middleware.meta_injection_middleware import (
        MetaInjectionMiddleware,
    )
    from amazon_ads_mcp.utils.http.rate_limit_headers import set_last_http_meta

    middleware = MetaInjectionMiddleware()

    async def call_next(_ctx):
        set_last_http_meta({"rate_limit": {"limit_per_second": 5.0}})
        return None

    result = await middleware.on_call_tool(_make_context(), call_next)
    assert result is None


# ---------------------------------------------------------------------------
# Pre-existing _meta is preserved
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_existing_meta_keys_preserved_when_rate_limit_added():
    from amazon_ads_mcp.middleware.meta_injection_middleware import (
        MetaInjectionMiddleware,
    )
    from amazon_ads_mcp.utils.http.rate_limit_headers import set_last_http_meta

    middleware = MetaInjectionMiddleware()

    async def call_next(_ctx):
        set_last_http_meta({"rate_limit": {"limit_per_second": 5.0}})
        return {
            "data": "ok",
            "_meta": {"normalized": [{"kind": "renamed", "from": "X", "to": "x"}]},
        }

    result = await middleware.on_call_tool(_make_context(), call_next)
    assert result["_meta"]["normalized"] == [
        {"kind": "renamed", "from": "X", "to": "x"}
    ]
    assert result["_meta"]["rate_limit"]["limit_per_second"] == 5.0


# ---------------------------------------------------------------------------
# Context-var lifecycle — cleared on entry
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_context_var_cleared_on_entry_so_stale_state_does_not_leak():
    """If a previous call left meta in the context-var, the next call must
    not inherit it."""
    from amazon_ads_mcp.middleware.meta_injection_middleware import (
        MetaInjectionMiddleware,
    )
    from amazon_ads_mcp.utils.http.rate_limit_headers import (
        get_last_http_meta,
        set_last_http_meta,
    )

    # Stale leftover from a prior call
    set_last_http_meta({"rate_limit": {"limit_per_second": 999.0}})

    middleware = MetaInjectionMiddleware()
    captured: dict[str, Any] = {}

    async def call_next(_ctx):
        captured["meta_seen"] = get_last_http_meta()
        return {"data": "ok"}

    await middleware.on_call_tool(_make_context(), call_next)

    # Inside the tool call, the context-var should have been reset.
    # (No new HTTP call made → still None.)
    assert captured["meta_seen"] is None


# ---------------------------------------------------------------------------
# Errors propagate
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fastmcp_tool_result_gets_meta_in_structured_content():
    """Integration: FastMCP wraps tool returns in ``ToolResult``. The
    middleware must inject ``_meta`` into ``structured_content`` so wire
    output carries rate-limit telemetry. Without this, agents never see
    ``_meta.rate_limit`` on success responses (Phase 5 tester gap)."""
    from fastmcp import FastMCP

    from amazon_ads_mcp.middleware.meta_injection_middleware import (
        MetaInjectionMiddleware,
    )
    from amazon_ads_mcp.utils.http.rate_limit_headers import set_last_http_meta

    mcp = FastMCP("test")
    mcp.add_middleware(MetaInjectionMiddleware())

    @mcp.tool(name="echo")
    async def echo() -> dict:
        set_last_http_meta(
            {"rate_limit": {"limit_per_second": 5.0, "remaining": 2.0}}
        )
        return {"ok": True}

    result = await mcp.call_tool("echo", {})
    assert "_meta" in result.structured_content
    assert result.structured_content["_meta"]["rate_limit"]["remaining"] == 2.0


@pytest.mark.asyncio
async def test_errors_from_call_next_propagate_unchanged():
    from amazon_ads_mcp.middleware.meta_injection_middleware import (
        MetaInjectionMiddleware,
    )

    middleware = MetaInjectionMiddleware()

    async def call_next(_ctx):
        raise RuntimeError("downstream broke")

    with pytest.raises(RuntimeError, match="downstream broke"):
        await middleware.on_call_tool(_make_context(), call_next)
