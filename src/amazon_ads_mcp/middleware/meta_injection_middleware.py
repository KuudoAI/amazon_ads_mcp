"""Inject ``_meta.rate_limit`` into successful tool responses.

When upstream Amazon Ads API responses include ``X-RateLimit-*`` /
``Retry-After`` headers, the resilient HTTP client captures them in a
context-var (``set_last_http_meta``). This middleware reads the context-var
after a tool call succeeds and merges the captured meta into the response
under ``_meta``.

Sits inside the envelope translator (so failures still emerge as v1 envelopes
with the same rate-limit telemetry) and inside the schema-normalization
middleware (so its ``_meta.normalized`` block is layered cleanly with this
``_meta.rate_limit`` block on the same response).

Behavior contract (verified by ``tests/unit/test_meta_injection_middleware.py``):

- Successful dict responses get ``_meta.rate_limit`` and/or
  ``_meta.retry_after_seconds`` populated **only when** the HTTP client
  captured headers during the call.
- Non-dict responses (lists, primitives, ``None``) pass through unchanged.
- Pre-existing ``_meta`` keys on the response are preserved; rate-limit
  data is merged additively.
- The context-var is cleared at the start of every call so stale state
  from a prior tool invocation cannot leak.
- Errors raised by ``call_next`` propagate unchanged; the envelope
  middleware (registered earlier in the chain) handles them.
"""

from __future__ import annotations

import logging
from typing import Any, Awaitable, Callable

from fastmcp.server.middleware import Middleware, MiddlewareContext

from ..utils.http.rate_limit_headers import (
    clear_last_http_meta,
    get_last_http_meta,
)
from .schema_normalization import get_current_normalization_events

logger = logging.getLogger(__name__)


class MetaInjectionMiddleware(Middleware):
    """Decorate successful dict responses with captured upstream HTTP meta."""

    async def on_call_tool(
        self,
        context: MiddlewareContext,
        call_next: Callable[[MiddlewareContext], Awaitable[Any]],
    ) -> Any:
        # Reset the context-var so meta from a prior call cannot leak in.
        clear_last_http_meta()

        result = await call_next(context)

        # Round 3-A: surface ``_meta.normalized`` on success so agents learn
        # when their input was rewritten by the schema-normalization
        # middleware. Previously only the error path threaded these events;
        # successful calls swallowed the rewrite silently.
        captured_http = get_last_http_meta()
        captured_normalized = get_current_normalization_events()
        if not captured_http and not captured_normalized:
            return result

        merged_captured: dict[str, Any] = dict(captured_http or {})
        if captured_normalized:
            merged_captured["normalized"] = captured_normalized

        # Direct dict response — straight merge.
        if isinstance(result, dict):
            return _merge_meta(result, merged_captured)

        # FastMCP wraps tool returns in a ``ToolResult`` whose
        # ``structured_content`` carries the dict the agent sees. Inject
        # ``_meta`` there (and rebuild ``content`` JSON to stay in sync) so
        # the wire output carries the rate-limit / normalized telemetry.
        structured = getattr(result, "structured_content", None)
        if isinstance(structured, dict):
            merged = _merge_meta(structured, merged_captured)
            try:
                result.structured_content = merged
            except Exception:
                pass
            _refresh_text_content(result, merged)
            return result

        return result


def _refresh_text_content(result: Any, merged: dict[str, Any]) -> None:
    """Best-effort: rewrite ``ToolResult.content[0].text`` to the JSON
    serialization of ``merged`` so the wire-level text content stays in
    sync with the structured_content we just decorated.
    """
    import json

    content = getattr(result, "content", None)
    if not content:
        return
    first = content[0] if isinstance(content, list) else None
    if first is None or not hasattr(first, "text"):
        return
    try:
        first.text = json.dumps(merged, ensure_ascii=True, separators=(",", ":"))
    except Exception:
        pass


def _merge_meta(response: dict[str, Any], captured: dict[str, Any]) -> dict[str, Any]:
    """Merge captured rate-limit meta into response['_meta'] additively.

    Returns a NEW dict; does not mutate the caller's response. Pre-existing
    ``_meta`` entries are preserved; only ``rate_limit`` / ``retry_after_seconds``
    keys are added.
    """
    out = dict(response)
    existing_meta = dict(out.get("_meta") or {})

    rate_limit = captured.get("rate_limit")
    if isinstance(rate_limit, dict) and rate_limit:
        existing_meta["rate_limit"] = rate_limit

    retry_after = captured.get("retry_after_seconds")
    if isinstance(retry_after, (int, float)):
        existing_meta["retry_after_seconds"] = float(retry_after)

    warnings = captured.get("warnings")
    if isinstance(warnings, list) and warnings:
        existing_meta["warnings"] = warnings

    normalized = captured.get("normalized")
    if isinstance(normalized, list) and normalized:
        existing_meta["normalized"] = normalized

    if existing_meta:
        out["_meta"] = existing_meta
    return out
