"""Round 14 Phase B — per-identity QueryAdvertiserAccount cache.

A focused, identity-scoped cache for the
``allv1_QueryAdvertiserAccount`` tool (and any same-named siblings
under different prefix conventions). Designed to absorb the
"CreateReport workflow calls QAA once at startup, then again on every
retry" pattern without the latency / upstream-load cost of redundant
calls.

Design principles:

  - **Cache only successful results.** Exceptions flow through
    untouched — caching a transient 4xx would lock the caller out
    for the full TTL.
  - **Identity-scoped key.** Cache key incorporates the active
    identity ID so multi-tenant deployments can never leak account
    lists across identities.
  - **Canonical-JSON key construction.** ``json.dumps(args,
    sort_keys=True, separators=(",", ":"), default=str)`` produces a
    deterministic key string regardless of dict insertion order.
    Hashed with SHA-256 to bound key length.
  - **Concurrency-safe.** Async lock around read/write/upstream so
    two concurrent identical requests serialize — exactly one
    upstream call, both observe the result.
  - **Bounded.** LRU eviction at ``MCP_QUERY_ADVERTISER_CACHE_SIZE``
    entries (default 256).
  - **Disabled cleanly.** ``MCP_QUERY_ADVERTISER_CACHE_TTL=0``
    short-circuits the middleware on every call — every request hits
    upstream.
  - **Observable.** Cache hits emit ``_meta.cache: {hit, age_seconds,
    key_id}`` so callers can see when they're being served from
    cache. The marker MERGES into existing ``_meta`` rather than
    replacing it (so MetaInjection's rate_limit / warnings survive).
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import logging
import time
from collections import OrderedDict
from typing import Any, Awaitable, Callable, Optional

from fastmcp.server.middleware import Middleware, MiddlewareContext

from ..config.settings import settings

logger = logging.getLogger(__name__)


def _build_cache_key(tool_name: str, identity_id: str, args: dict) -> str:
    """Canonical SHA-256 key from ``(tool_name, identity_id, args)``.

    Uses ``json.dumps(sort_keys=True, separators=(",", ":"),
    default=str)`` so the key is:

      - deterministic (same inputs → same key, regardless of dict
        insertion order),
      - bounded (SHA-256 hex, 64 chars),
      - robust against non-JSON-serializable values via
        ``default=str`` (datetime / enum / one-off objects).
    """
    try:
        canonical = json.dumps(
            args or {},
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
    except Exception:  # pragma: no cover - defensive
        canonical = repr(args)
    raw = f"{tool_name}|{identity_id}|{canonical}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _get_active_identity_id() -> Optional[str]:
    """Resolve the active identity ID via the auth manager.

    Stubbed in tests via ``monkeypatch.setattr(module,
    "_get_active_identity_id", ...)``. Returns ``None`` when no
    identity is bound — middleware will short-circuit to upstream
    rather than risk a cross-identity cache key collision.
    """
    try:
        from ..auth.manager import get_auth_manager
    except Exception:  # pragma: no cover - defensive
        return None
    try:
        mgr = get_auth_manager()
    except Exception:  # pragma: no cover - defensive
        return None
    if mgr is None:
        return None
    try:
        if hasattr(mgr, "get_active_identity_id"):
            ident_id = mgr.get_active_identity_id()
            if ident_id:
                return str(ident_id)
        ident = mgr.get_active_identity() if hasattr(mgr, "get_active_identity") else None
        if ident is None:
            return None
        # Identity may be a Pydantic model with .id, or a dict.
        if hasattr(ident, "id"):
            return str(ident.id)
        if isinstance(ident, dict):
            return str(ident.get("id") or ident.get("identity_id") or "")
    except Exception:  # pragma: no cover - defensive
        return None
    return None


class _CacheEntry:
    __slots__ = ("payload", "stored_at", "original_for_shape")

    def __init__(
        self, payload: dict, stored_at: float, original_for_shape: Any
    ) -> None:
        # ``payload`` is the cached structured dict (deep-copied at store
        # time so future mutations cannot leak back into cache).
        # ``original_for_shape`` retains a reference to the wire shape
        # (dict or ToolResult) the original call returned, so cache hits
        # can rebuild a same-shaped response for the rest of the chain.
        self.payload = payload
        self.stored_at = stored_at
        self.original_for_shape = original_for_shape


class QueryAdvertiserCacheMiddleware(Middleware):
    """Per-identity LRU cache for QueryAdvertiserAccount calls."""

    def __init__(self) -> None:
        # Ordered dict gives us O(1) LRU via move_to_end + popitem(last=False).
        self._cache: OrderedDict[str, _CacheEntry] = OrderedDict()
        self._lock = asyncio.Lock()

    @staticmethod
    def _is_target_tool(tool_name: Optional[str]) -> bool:
        if not tool_name:
            return False
        return "QueryAdvertiserAccount" in tool_name

    def _get_fresh(self, key: str, ttl: int) -> Optional[_CacheEntry]:
        """Return the cached entry if it's still within TTL, else
        evict and return None. Caller must hold the lock."""
        entry = self._cache.get(key)
        if entry is None:
            return None
        age = time.monotonic() - entry.stored_at
        if age > ttl:
            self._cache.pop(key, None)
            return None
        # LRU touch.
        self._cache.move_to_end(key)
        return entry

    def _store(
        self, key: str, payload: dict, original: Any, max_size: int
    ) -> None:
        """Store (or refresh) a cache entry. Caller must hold the lock.

        ``payload`` is the cached structured dict; ``original`` is the
        wire-shape sample (dict or ToolResult) so hits can rebuild a
        same-shaped response.
        """
        if key in self._cache:
            self._cache.pop(key)
        self._cache[key] = _CacheEntry(payload, time.monotonic(), original)
        # Evict oldest entries above the cap.
        while len(self._cache) > max_size:
            self._cache.popitem(last=False)

    @staticmethod
    def _extract_structured(payload: Any) -> Optional[dict]:
        """Return the dict payload that should be cached.

        Handles both wire shapes:
          - Direct dict (unit-test path, dispatch returns raw JSON)
          - FastMCP ``ToolResult`` (production path, OpenAPI tool wrapped)
            — pull ``structured_content`` and deep-copy so future mutations
            never leak into the cached entry.
        """
        if isinstance(payload, dict):
            return copy.deepcopy(payload)
        structured = getattr(payload, "structured_content", None)
        if isinstance(structured, dict):
            return copy.deepcopy(structured)
        return None

    @staticmethod
    def _build_hit_payload(
        original: Any, cached_dict: dict, key: str, age_seconds: float
    ) -> Any:
        """Construct the cache-hit response.

        Mirrors the original payload's wire shape (dict or ``ToolResult``)
        so the rest of the middleware chain — and FastMCP's runtime —
        receives the same Python type it would have on a miss. Merges
        ``_meta.cache`` into existing ``_meta`` rather than replacing it,
        preserving MetaInjection's injected fields when present.
        """
        out = copy.deepcopy(cached_dict)
        existing_meta = out.get("_meta")
        if isinstance(existing_meta, dict):
            new_meta = dict(existing_meta)
        else:
            new_meta = {}
        new_meta["cache"] = {
            "hit": True,
            "age_seconds": round(age_seconds, 3),
            "key_id": key[:12],
        }
        out["_meta"] = new_meta

        if isinstance(original, dict):
            return out

        # ToolResult path: rebuild a fresh wrapper so ``content`` and
        # ``structured_content`` stay in sync. We import lazily to avoid
        # the import cost on the dict-only unit-test path.
        try:
            from fastmcp.tools.tool import ToolResult  # type: ignore
        except Exception:  # pragma: no cover - defensive
            try:
                from fastmcp.tools.base import ToolResult  # type: ignore
            except Exception:
                return out
        try:
            return ToolResult(structured_content=out)
        except Exception:  # pragma: no cover - defensive
            return out

    async def on_call_tool(
        self,
        context: MiddlewareContext,
        call_next: Callable[[MiddlewareContext], Awaitable[Any]],
    ) -> Any:
        message = getattr(context, "message", None)
        tool_name = getattr(message, "name", None)

        # Fast path: not our target tool → pass through unchanged.
        if not self._is_target_tool(tool_name):
            return await call_next(context)

        ttl = int(getattr(settings, "mcp_query_advertiser_cache_ttl", 60) or 0)
        max_size = int(
            getattr(settings, "mcp_query_advertiser_cache_size", 256) or 256
        )
        if ttl <= 0:
            # Caching disabled — every call hits upstream.
            return await call_next(context)

        identity_id = _get_active_identity_id()
        if not identity_id:
            # No active identity → cache key would be unsafe. Always
            # short-circuit to upstream (never serve a foreign-identity
            # cached result).
            return await call_next(context)

        args = dict(getattr(message, "arguments", None) or {})
        key = _build_cache_key(tool_name, identity_id, args)

        async with self._lock:
            entry = self._get_fresh(key, ttl)
            if entry is not None:
                age = time.monotonic() - entry.stored_at
                logger.debug(
                    "query_advertiser_cache hit",
                    extra={
                        "event": "query_advertiser_cache_hit",
                        "key_id": key[:12],
                        "age_seconds": age,
                    },
                )
                # ``entry.payload`` is the cached structured dict; rebuild
                # a wrapper that matches the original wire shape. We use
                # the cached dict itself as the "original" stand-in
                # (sentinel for dict-shape) since by the time we hit, the
                # original ToolResult wrapper isn't around — but we
                # remembered the wire shape via ``entry.was_wrapped``.
                return self._build_hit_payload(
                    entry.original_for_shape, entry.payload, key, age
                )

            # Miss inside the lock: call upstream while holding the
            # lock so concurrent requests with the same key serialize.
            # Without this, two concurrent calls would both miss and
            # both invoke upstream, defeating the cache.
            payload = await call_next(context)
            # Cache only successful results — exceptions propagated
            # naturally above (the await raised, we never reach here).
            structured = self._extract_structured(payload)
            if structured is not None:
                # Sentinel for shape: a deep-copied dict represents
                # "dict-wire" and an empty ToolResult-equivalent represents
                # "wrapped-wire". We just pass the live ``payload`` so the
                # next-call shape detection mirrors what the agent saw.
                self._store(key, structured, payload, max_size)
            return payload


def create_query_advertiser_cache_middleware() -> QueryAdvertiserCacheMiddleware:
    """Factory used by :class:`server.server_builder.ServerBuilder`."""
    return QueryAdvertiserCacheMiddleware()
