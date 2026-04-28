"""Round 14 Phase B integration — wire-level cache short-circuit proof.

Spins the cache middleware against a mock upstream and asserts the
second identical call DOES NOT issue a fresh upstream invocation.
Lighter than full FastMCP server-build; we drive the middleware
directly with mocked auth context and a counted upstream callable —
which proves the cache short-circuits the dispatch chain end-to-end
without depending on httpx mock plumbing that may diverge between
test environments.
"""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest

from amazon_ads_mcp.middleware.query_advertiser_cache import (
    QueryAdvertiserCacheMiddleware,
)


def _force_cache_settings(monkeypatch, *, ttl: int = 60) -> None:
    from amazon_ads_mcp.middleware import query_advertiser_cache as mod

    class _S:
        mcp_query_advertiser_cache_ttl = ttl
        mcp_query_advertiser_cache_size = 256

    monkeypatch.setattr(mod, "settings", _S())


def _force_active_identity(monkeypatch, identity_id: str) -> None:
    from amazon_ads_mcp.middleware import query_advertiser_cache as mod

    monkeypatch.setattr(mod, "_get_active_identity_id", lambda: identity_id)


class _Ctx:
    def __init__(self, tool_name: str, args: dict) -> None:
        self.message = MagicMock()
        self.message.name = tool_name
        self.message.arguments = args
        self.fastmcp_context = self


@pytest.mark.asyncio
async def test_wire_cache_short_circuits_dispatch(monkeypatch) -> None:
    """End-to-end: middleware short-circuits upstream dispatch on the
    second identical call. Counts the number of times the dispatch
    function was actually invoked — proves the cache reaches before
    any wire call would have happened."""
    _force_cache_settings(monkeypatch)
    _force_active_identity(monkeypatch, "test-identity")

    upstream_invocations = []

    async def fake_dispatch(ctx) -> dict:
        upstream_invocations.append(
            (ctx.message.name, dict(ctx.message.arguments))
        )
        return {
            "accounts": [
                {"advertiserAccountId": "amzn1.ads-account.g.test"},
            ],
            "_meta": {"rate_limit": {"remaining": 100}},
        }

    mw = QueryAdvertiserCacheMiddleware()
    args = {"advertiserAccountIdFilter": ["amzn1.ads-account.g.test"]}

    res1 = await mw.on_call_tool(
        _Ctx("allv1_QueryAdvertiserAccount", args), fake_dispatch
    )
    res2 = await mw.on_call_tool(
        _Ctx("allv1_QueryAdvertiserAccount", args), fake_dispatch
    )

    # Exactly one upstream invocation across two calls.
    assert len(upstream_invocations) == 1, (
        f"second call should have short-circuited; "
        f"got {len(upstream_invocations)} invocations"
    )

    # First call has no cache marker; second call carries hit metadata.
    res1_meta = (res1 or {}).get("_meta") or {}
    res2_meta = (res2 or {}).get("_meta") or {}
    assert "cache" not in res1_meta or not res1_meta.get("cache", {}).get("hit")
    assert res2_meta.get("cache", {}).get("hit") is True

    # Cached payload preserves the original _meta fields (rate_limit
    # not clobbered by the cache marker — middleware-order safety).
    assert res2_meta.get("rate_limit", {}).get("remaining") == 100

    # Both responses carry the same primary payload.
    assert res1["accounts"] == res2["accounts"]


@pytest.mark.asyncio
async def test_wire_cache_high_concurrency_burst(monkeypatch) -> None:
    """Realistic burst pattern: 10 simultaneous identical
    QueryAdvertiserAccount calls (e.g. parallel CreateReport
    workflows) collapse to exactly ONE upstream dispatch."""
    _force_cache_settings(monkeypatch)
    _force_active_identity(monkeypatch, "burst-identity")

    upstream_calls = [0]

    async def slow_dispatch(ctx) -> dict:
        upstream_calls[0] += 1
        # Simulate a slow upstream so the burst races within the
        # critical section.
        await asyncio.sleep(0.01)
        return {"accounts": [{"advertiserAccountId": "amzn1.ads-account.g.burst"}]}

    mw = QueryAdvertiserCacheMiddleware()
    args = {}

    results = await asyncio.gather(*[
        mw.on_call_tool(
            _Ctx("allv1_QueryAdvertiserAccount", args), slow_dispatch
        )
        for _ in range(10)
    ])

    assert upstream_calls[0] == 1, (
        f"10 concurrent identical calls should serialize to ONE "
        f"upstream invocation; got {upstream_calls[0]}"
    )
    # All 10 responses agree on the payload.
    expected = results[0]["accounts"]
    for r in results:
        assert r["accounts"] == expected


@pytest.mark.asyncio
async def test_wire_cache_handles_toolresult_wrapper(monkeypatch) -> None:
    """Round 14 wire-shape regression: production OpenAPI tools return
    a FastMCP ``ToolResult`` (not a raw dict). This exercises that path
    explicitly — the middleware must extract ``structured_content`` for
    the cache, and on hit rebuild a same-shaped ``ToolResult`` with
    ``_meta.cache`` injected. Pre-fix, the cache stored the wrapper
    object and ``_annotate_cache_hit``'s ``isinstance(payload, dict)``
    short-circuit dropped the marker on the wire."""
    from fastmcp.tools.tool import ToolResult  # type: ignore

    _force_cache_settings(monkeypatch)
    _force_active_identity(monkeypatch, "wrapper-identity")

    invocations = [0]

    async def wrapped_dispatch(ctx) -> ToolResult:
        invocations[0] += 1
        return ToolResult(
            structured_content={
                "accounts": [
                    {"advertiserAccountId": "amzn1.ads-account.g.wrapped"}
                ],
                "_meta": {"rate_limit": {"remaining": 42}},
            }
        )

    mw = QueryAdvertiserCacheMiddleware()
    args = {"advertiserAccountIdFilter": ["amzn1.ads-account.g.wrapped"]}

    res1 = await mw.on_call_tool(
        _Ctx("allv1_QueryAdvertiserAccount", args), wrapped_dispatch
    )
    res2 = await mw.on_call_tool(
        _Ctx("allv1_QueryAdvertiserAccount", args), wrapped_dispatch
    )

    # Exactly one upstream invocation across two calls.
    assert invocations[0] == 1, (
        f"second call should have short-circuited; "
        f"got {invocations[0]} invocations"
    )

    # Both responses preserve the ToolResult shape (so the rest of the
    # middleware chain — and the FastMCP runtime — receive the type
    # they expect).
    assert isinstance(res1, ToolResult)
    assert isinstance(res2, ToolResult)

    # Cached structured_content carries the original payload AND the
    # cache marker on hit. Rate-limit field from MetaInjection-style
    # _meta is preserved (merge, not replace).
    s1 = res1.structured_content or {}
    s2 = res2.structured_content or {}
    assert "cache" not in (s1.get("_meta") or {})
    s2_cache = (s2.get("_meta") or {}).get("cache") or {}
    assert s2_cache.get("hit") is True
    assert isinstance(s2_cache.get("age_seconds"), (int, float))
    assert isinstance(s2_cache.get("key_id"), str) and s2_cache["key_id"]
    assert (s2.get("_meta") or {}).get("rate_limit", {}).get("remaining") == 42
    assert s2.get("accounts") == s1.get("accounts")
