"""Round 14 Phase B — per-identity QueryAdvertiserAccount cache tests.

Pinned contract:
  - First call → cache miss → upstream invoked → result cached.
  - Second identical call within TTL → cache hit, upstream NOT
    re-invoked.
  - Different identity → fresh upstream call (multi-tenant boundary).
  - Different args → fresh upstream call.
  - TTL expiry → cache evicted, fresh upstream call.
  - LRU bound respected.
  - ``MCP_QUERY_ADVERTISER_CACHE_TTL=0`` disables caching entirely.
  - ``_meta.cache: {hit: true, age_seconds: N, key_id: <hash>}`` on
    cached responses.
  - Canonical-JSON cache key: arg-order-independent.
  - **Failure NOT cached**: transient errors don't become sticky
    for the TTL.
  - **Concurrency safety**: two coroutines with same key serialize
    on the lock, exactly ONE upstream call observed.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from amazon_ads_mcp.middleware.query_advertiser_cache import (
    QueryAdvertiserCacheMiddleware,
    _build_cache_key,
)


def _force_cache_settings(monkeypatch, *, ttl: int = 60, size: int = 256) -> None:
    """Override settings on the cache module."""
    from amazon_ads_mcp.middleware import query_advertiser_cache as mod

    class _S:
        mcp_query_advertiser_cache_ttl = ttl
        mcp_query_advertiser_cache_size = size

    monkeypatch.setattr(mod, "settings", _S())


def _force_active_identity(monkeypatch, identity_id: str | None) -> None:
    """Stub the active-identity getter so tests don't need real auth."""
    from amazon_ads_mcp.middleware import query_advertiser_cache as mod

    monkeypatch.setattr(mod, "_get_active_identity_id", lambda: identity_id)


class _Ctx:
    def __init__(self, tool_name: str, args: dict) -> None:
        self.message = MagicMock()
        self.message.name = tool_name
        self.message.arguments = args
        self.fastmcp_context = self


# ---- Cache key shape ---------------------------------------------------


def test_cache_key_is_canonical_arg_order_independent() -> None:
    """Same args, different insertion order → same cache key."""
    k1 = _build_cache_key("allv1_QueryAdvertiserAccount", "id-1",
                          {"a": 1, "b": 2, "c": [1, 2, 3]})
    k2 = _build_cache_key("allv1_QueryAdvertiserAccount", "id-1",
                          {"c": [1, 2, 3], "b": 2, "a": 1})
    assert k1 == k2


def test_cache_key_separates_identities() -> None:
    """Same args, different identity → different cache key."""
    k1 = _build_cache_key("allv1_QueryAdvertiserAccount", "id-1", {})
    k2 = _build_cache_key("allv1_QueryAdvertiserAccount", "id-2", {})
    assert k1 != k2


def test_cache_key_separates_args() -> None:
    """Same identity, different args → different cache key."""
    k1 = _build_cache_key("allv1_QueryAdvertiserAccount", "id-1",
                          {"advertiserAccountIdFilter": ["A"]})
    k2 = _build_cache_key("allv1_QueryAdvertiserAccount", "id-1",
                          {"advertiserAccountIdFilter": ["B"]})
    assert k1 != k2


def test_cache_key_handles_non_json_serializable_values() -> None:
    """``default=str`` keeps the key generation robust against one-off
    enum/datetime args without crashing."""
    from datetime import datetime

    k = _build_cache_key("allv1_QueryAdvertiserAccount", "id-1",
                         {"timestamp": datetime(2026, 4, 28)})
    assert isinstance(k, str) and len(k) > 0


# ---- Cache behavior — miss / hit / boundaries --------------------------


@pytest.mark.asyncio
async def test_first_call_misses_cache_and_invokes_upstream(monkeypatch) -> None:
    _force_cache_settings(monkeypatch)
    _force_active_identity(monkeypatch, "id-1")

    upstream = AsyncMock(return_value={"accounts": [{"advertiserAccountId": "A1"}]})
    mw = QueryAdvertiserCacheMiddleware()
    ctx = _Ctx("allv1_QueryAdvertiserAccount", {})
    result = await mw.on_call_tool(ctx, upstream)

    assert upstream.await_count == 1
    assert result.get("accounts") == [{"advertiserAccountId": "A1"}]
    # First call has NO cache hit marker.
    meta = (result or {}).get("_meta") or {}
    assert "cache" not in meta or not meta.get("cache", {}).get("hit", False)


@pytest.mark.asyncio
async def test_second_identical_call_hits_cache(monkeypatch) -> None:
    _force_cache_settings(monkeypatch)
    _force_active_identity(monkeypatch, "id-1")

    upstream = AsyncMock(return_value={"accounts": [{"advertiserAccountId": "A1"}]})
    mw = QueryAdvertiserCacheMiddleware()
    ctx = _Ctx("allv1_QueryAdvertiserAccount", {})
    await mw.on_call_tool(ctx, upstream)
    upstream.reset_mock()
    result2 = await mw.on_call_tool(ctx, upstream)

    assert upstream.await_count == 0, "cache hit should bypass upstream"
    meta = (result2 or {}).get("_meta") or {}
    cache_meta = meta.get("cache") or {}
    assert cache_meta.get("hit") is True
    assert isinstance(cache_meta.get("age_seconds"), (int, float))
    assert cache_meta.get("age_seconds") >= 0
    assert isinstance(cache_meta.get("key_id"), str)


@pytest.mark.asyncio
async def test_different_identity_isolated_from_cache(monkeypatch) -> None:
    """Multi-tenant safety: identity B never observes identity A's
    cached account list."""
    _force_cache_settings(monkeypatch)

    upstream = AsyncMock(side_effect=[
        {"accounts": [{"advertiserAccountId": "FOR_A"}]},
        {"accounts": [{"advertiserAccountId": "FOR_B"}]},
    ])
    mw = QueryAdvertiserCacheMiddleware()

    _force_active_identity(monkeypatch, "id-A")
    res_a = await mw.on_call_tool(_Ctx("allv1_QueryAdvertiserAccount", {}), upstream)

    _force_active_identity(monkeypatch, "id-B")
    res_b = await mw.on_call_tool(_Ctx("allv1_QueryAdvertiserAccount", {}), upstream)

    assert upstream.await_count == 2, "both identities must hit upstream"
    assert res_a["accounts"][0]["advertiserAccountId"] == "FOR_A"
    assert res_b["accounts"][0]["advertiserAccountId"] == "FOR_B"


@pytest.mark.asyncio
async def test_different_args_isolated_from_cache(monkeypatch) -> None:
    _force_cache_settings(monkeypatch)
    _force_active_identity(monkeypatch, "id-1")

    upstream = AsyncMock(side_effect=[
        {"accounts": ["WITH_A"]},
        {"accounts": ["WITH_B"]},
    ])
    mw = QueryAdvertiserCacheMiddleware()

    await mw.on_call_tool(
        _Ctx("allv1_QueryAdvertiserAccount", {"advertiserAccountIdFilter": ["A"]}),
        upstream,
    )
    await mw.on_call_tool(
        _Ctx("allv1_QueryAdvertiserAccount", {"advertiserAccountIdFilter": ["B"]}),
        upstream,
    )

    assert upstream.await_count == 2


@pytest.mark.asyncio
async def test_ttl_expiry_evicts_entry(monkeypatch) -> None:
    _force_cache_settings(monkeypatch, ttl=60)
    _force_active_identity(monkeypatch, "id-1")

    fake_time = [1000.0]
    monkeypatch.setattr(
        "amazon_ads_mcp.middleware.query_advertiser_cache.time.monotonic",
        lambda: fake_time[0],
    )

    upstream = AsyncMock(side_effect=[
        {"accounts": ["FIRST"]},
        {"accounts": ["SECOND"]},
    ])
    mw = QueryAdvertiserCacheMiddleware()
    ctx = _Ctx("allv1_QueryAdvertiserAccount", {})

    await mw.on_call_tool(ctx, upstream)
    fake_time[0] += 61.0  # past TTL
    res2 = await mw.on_call_tool(ctx, upstream)

    assert upstream.await_count == 2
    assert res2["accounts"] == ["SECOND"]


@pytest.mark.asyncio
async def test_ttl_zero_disables_caching(monkeypatch) -> None:
    _force_cache_settings(monkeypatch, ttl=0)
    _force_active_identity(monkeypatch, "id-1")

    upstream = AsyncMock(return_value={"accounts": ["X"]})
    mw = QueryAdvertiserCacheMiddleware()
    ctx = _Ctx("allv1_QueryAdvertiserAccount", {})
    await mw.on_call_tool(ctx, upstream)
    await mw.on_call_tool(ctx, upstream)
    assert upstream.await_count == 2, "TTL=0 must skip cache entirely"


@pytest.mark.asyncio
async def test_lru_bound_evicts_oldest(monkeypatch) -> None:
    _force_cache_settings(monkeypatch, size=3)
    _force_active_identity(monkeypatch, "id-1")

    upstream = AsyncMock(side_effect=lambda c: {"accounts": [c.message.arguments["k"]]})
    mw = QueryAdvertiserCacheMiddleware()

    for i in range(4):
        await mw.on_call_tool(
            _Ctx("allv1_QueryAdvertiserAccount", {"k": f"k{i}"}),
            upstream,
        )

    # Re-call k0 — should miss because cap=3 evicted oldest.
    upstream.reset_mock()
    await mw.on_call_tool(
        _Ctx("allv1_QueryAdvertiserAccount", {"k": "k0"}),
        upstream,
    )
    assert upstream.await_count == 1, "LRU should have evicted k0"


# ---- Failure NOT cached -------------------------------------------------


@pytest.mark.asyncio
async def test_failure_not_cached_transient_error_recovers(monkeypatch) -> None:
    """Critical safety: caching an exception turns transient failures
    into sticky errors for the TTL window. The next call MUST re-
    invoke upstream after a failure."""
    _force_cache_settings(monkeypatch)
    _force_active_identity(monkeypatch, "id-1")

    call_results: list = [
        RuntimeError("transient upstream blip"),
        {"accounts": ["RECOVERED"]},
    ]

    async def upstream(ctx):
        result = call_results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result

    mw = QueryAdvertiserCacheMiddleware()
    ctx = _Ctx("allv1_QueryAdvertiserAccount", {})

    with pytest.raises(RuntimeError):
        await mw.on_call_tool(ctx, upstream)

    # Second call MUST re-invoke upstream (failure was NOT cached).
    res2 = await mw.on_call_tool(ctx, upstream)
    assert res2["accounts"] == ["RECOVERED"]


# ---- Concurrency safety -------------------------------------------------


@pytest.mark.asyncio
async def test_concurrent_identical_requests_serialize_to_one_upstream(monkeypatch) -> None:
    """Two coroutines issuing the same key must serialize on the
    cache lock — exactly ONE upstream call, both get the same payload."""
    _force_cache_settings(monkeypatch)
    _force_active_identity(monkeypatch, "id-1")

    upstream_calls = [0]

    async def slow_upstream(ctx):
        upstream_calls[0] += 1
        # Yield to let the other coroutine race.
        await asyncio.sleep(0.05)
        return {"accounts": ["X"]}

    mw = QueryAdvertiserCacheMiddleware()
    ctx = _Ctx("allv1_QueryAdvertiserAccount", {})

    results = await asyncio.gather(
        mw.on_call_tool(ctx, slow_upstream),
        mw.on_call_tool(ctx, slow_upstream),
    )

    assert upstream_calls[0] == 1, (
        f"concurrent identical requests must serialize; upstream "
        f"called {upstream_calls[0]} times"
    )
    assert all(r["accounts"] == ["X"] for r in results)


# ---- _meta.cache merging (middleware-order regression) ------------------


@pytest.mark.asyncio
async def test_cache_meta_merges_not_replaces_existing_meta(monkeypatch) -> None:
    """When the cached payload already carries ``_meta`` (e.g. from
    upstream MetaInjectionMiddleware), the cache hit must MERGE
    ``_meta.cache`` into the existing dict, not replace ``_meta``
    entirely. Pinned per the middleware-order regression contract."""
    _force_cache_settings(monkeypatch)
    _force_active_identity(monkeypatch, "id-1")

    upstream = AsyncMock(return_value={
        "accounts": ["A1"],
        "_meta": {"rate_limit": {"remaining": 100}, "warnings": ["soft"]},
    })
    mw = QueryAdvertiserCacheMiddleware()
    ctx = _Ctx("allv1_QueryAdvertiserAccount", {})

    await mw.on_call_tool(ctx, upstream)
    res2 = await mw.on_call_tool(ctx, upstream)

    meta = (res2 or {}).get("_meta") or {}
    # Cache marker present.
    assert meta.get("cache", {}).get("hit") is True
    # Existing fields preserved (not clobbered).
    assert meta.get("rate_limit", {}).get("remaining") == 100
    assert meta.get("warnings") == ["soft"]


@pytest.mark.asyncio
async def test_no_active_identity_falls_through_to_upstream(monkeypatch) -> None:
    """When no identity is bound (rare; agent in execute block before
    set_active_identity), cache short-circuits to upstream — never
    serves a foreign-identity result."""
    _force_cache_settings(monkeypatch)
    _force_active_identity(monkeypatch, None)

    upstream = AsyncMock(return_value={"accounts": ["X"]})
    mw = QueryAdvertiserCacheMiddleware()
    ctx = _Ctx("allv1_QueryAdvertiserAccount", {})
    await mw.on_call_tool(ctx, upstream)
    await mw.on_call_tool(ctx, upstream)
    assert upstream.await_count == 2, (
        "no active identity → must always hit upstream (safety)"
    )


@pytest.mark.asyncio
async def test_non_query_advertiser_tool_falls_through(monkeypatch) -> None:
    """Middleware fires only for QueryAdvertiserAccount-named tools.
    Other tools pass through unchanged."""
    _force_cache_settings(monkeypatch)
    _force_active_identity(monkeypatch, "id-1")

    upstream = AsyncMock(return_value={"data": "passthrough"})
    mw = QueryAdvertiserCacheMiddleware()
    ctx = _Ctx("allv1_AdsApiv1CreateReport", {"reports": []})
    await mw.on_call_tool(ctx, upstream)
    await mw.on_call_tool(ctx, upstream)
    assert upstream.await_count == 2, (
        "non-QAA tool must not be cached"
    )
