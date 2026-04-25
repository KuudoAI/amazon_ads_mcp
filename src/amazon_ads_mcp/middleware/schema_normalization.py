"""Schema-driven pre-flight key normalization middleware (v1 contract).

Implements the cross-server contract described in
``openbridge-mcp/CONTRACT.md``. Independent of the declarative aliasing
system in ``server/sidecar_middleware.py`` (which handles operation-specific
overlays such as ``reportId`` → ``reportIds`` for v1 reports).

Behavior contract (verified by ``tests/unit/test_schema_normalization.py``):

- Unique schema match → rewrite to canonical
- Ambiguous match → unchanged (passes through; emits
  ``unknown_field_passed_through``)
- No match → unchanged (passes through; emits
  ``unknown_field_passed_through``)
- Canonical present alongside alias → drop alias (emits ``dropped_alias``)
- Schema is array-typed but client provided scalar → wrap to single-item
  list (emits ``coerced``)

Master switch: ``MCP_SCHEMA_KEY_NORMALIZATION_ENABLED`` (default true).
Telemetry gate: ``MCP_SCHEMA_KEY_NORMALIZATION_META`` (default false).
"""

from __future__ import annotations

import logging
from contextvars import ContextVar
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

from fastmcp.server.middleware import Middleware, MiddlewareContext

from ..config.settings import settings

logger = logging.getLogger(__name__)


#: Per-request capture of normalization events. The error envelope middleware
#: reads this to populate ``_meta.normalized`` when a tool call fails after
#: normalization has run.
_CURRENT_NORMALIZATION_EVENTS: ContextVar[Optional[List[Dict[str, Any]]]] = (
    ContextVar("ads_current_normalization_events", default=None)
)


def get_current_normalization_events() -> Optional[List[Dict[str, Any]]]:
    """Return the in-flight normalization events, or None if not set."""
    return _CURRENT_NORMALIZATION_EVENTS.get()


# ---------------------------------------------------------------------------
# Public API — pure rewrite_args used by middleware and Code Mode bridge
# ---------------------------------------------------------------------------


async def rewrite_args(
    tool_name: str,
    args: Optional[Dict[str, Any]],
    *,
    server: Any | None = None,
    fastmcp_context: Any | None = None,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Apply schema-driven normalization to ``args`` for ``tool_name``.

    :param tool_name: The tool name to look up in the FastMCP server.
    :param args: The caller-supplied argument dict. ``None`` is treated as
        an empty dict.
    :param server: The FastMCP server instance (preferred for direct lookup).
    :param fastmcp_context: A FastMCP middleware context (alternative
        lookup path used by ``on_call_tool``).
    :returns: A tuple ``(rewritten_args, events)``. When normalization is
        disabled or no events fire, the returned dict is the *same object*
        as the caller's input where possible.
    """
    if not settings.mcp_schema_key_normalization_enabled:
        return dict(args or {}) if args is None else (args or {}), []

    rewritten: Dict[str, Any] = dict(args or {})
    if not rewritten:
        return rewritten, []

    properties = await _get_tool_properties(
        tool_name, server=server, fastmcp_context=fastmcp_context
    )
    if not properties:
        return rewritten, []

    return _normalize_args_with_schema(rewritten, properties)


# ---------------------------------------------------------------------------
# Middleware class
# ---------------------------------------------------------------------------


class SchemaKeyNormalizationMiddleware(Middleware):
    """FastMCP middleware that runs schema-driven key normalization before
    tool dispatch.

    Sits OUTSIDE downstream guardrails (so guardrails see canonicalized
    keys) and INSIDE the envelope translator (so any error after
    normalization is reported with the canonical key set).
    """

    async def on_call_tool(
        self,
        context: MiddlewareContext,
        call_next: Callable[[MiddlewareContext], Awaitable[Any]],
    ) -> Any:
        message = getattr(context, "message", None)
        tool_name = getattr(message, "name", None)
        if not tool_name:
            return await call_next(context)

        raw_args: Dict[str, Any] = dict(getattr(message, "arguments", None) or {})
        rewritten, events = await rewrite_args(
            tool_name,
            raw_args,
            fastmcp_context=getattr(context, "fastmcp_context", None),
        )

        token: Any | None = None
        if settings.mcp_schema_key_normalization_meta and events:
            token = _CURRENT_NORMALIZATION_EVENTS.set(events)

        try:
            if rewritten != raw_args:
                try:
                    message.arguments = rewritten
                except Exception:
                    try:
                        new_message = message.model_copy(update={"arguments": rewritten})
                        context.message = new_message  # type: ignore[assignment]
                    except Exception as exc:  # pragma: no cover - defensive
                        logger.warning(
                            "SchemaKeyNormalizationMiddleware: could not replace "
                            "arguments on %s: %s",
                            tool_name,
                            exc,
                        )
            return await call_next(context)
        finally:
            if token is not None:
                _CURRENT_NORMALIZATION_EVENTS.reset(token)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _normalize_args_with_schema(
    args: Dict[str, Any],
    properties: Dict[str, Any],
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Build a normalized-key index of the schema and rewrite ``args``."""

    index: Dict[str, List[str]] = {}
    for key in properties.keys():
        token = _normalize_key(key)
        if not token:
            continue
        index.setdefault(token, []).append(key)

    rewritten: Dict[str, Any] = dict(args)
    changed = False
    events: List[Dict[str, Any]] = []

    for src in list(args.keys()):
        if src in properties:
            # Already canonical; no event needed.
            continue
        token = _normalize_key(src)
        if not token:
            continue
        targets = index.get(token) or []
        if len(targets) != 1:
            events.append(
                {
                    "kind": "unknown_field_passed_through",
                    "field": src,
                    "reason": "no_schema_match",
                }
            )
            continue
        target = targets[0]
        src_val = rewritten.get(src)
        if target in rewritten and rewritten.get(target) not in (None, ""):
            # Canonical already present; drop alias so strict schemas accept input.
            rewritten.pop(src, None)
            changed = True
            events.append(
                {
                    "kind": "dropped_alias",
                    "from": src,
                    "reason": "canonical_key_also_present",
                    "canonical": target,
                }
            )
            continue
        mapped = _coerce_value_for_property(src_val, properties[target])
        rewritten[target] = mapped
        rewritten.pop(src, None)
        changed = True
        events.append(
            {
                "kind": "renamed",
                "from": src,
                "to": target,
                "reason": "schema_canonical_key",
            }
        )
        if mapped is not src_val:
            events.append(
                {
                    "kind": "coerced",
                    "field": target,
                    "from_type": type(src_val).__name__,
                    "to_type": type(mapped).__name__,
                    "reason": "schema_array_wrap",
                }
            )

    return (rewritten if changed else args), events


async def _get_tool_properties(
    tool_name: str,
    *,
    server: Any | None = None,
    fastmcp_context: Any | None = None,
) -> Dict[str, Any]:
    """Resolve the tool's input schema ``properties`` from the FastMCP server.

    Prefers ``server`` when supplied (direct unit-test path). Falls back to
    ``fastmcp_context.fastmcp`` for the in-server middleware path.
    """
    fastmcp_server = server
    if fastmcp_server is None:
        fastmcp_server = getattr(fastmcp_context, "fastmcp", None)
    if fastmcp_server is None:
        return {}
    try:
        tool = await fastmcp_server.get_tool(tool_name)
    except Exception:
        return {}
    if tool is None:
        return {}

    params = getattr(tool, "parameters", None)
    if not isinstance(params, dict):
        return {}
    props = params.get("properties")
    if not isinstance(props, dict):
        return {}
    return props


def _normalize_key(name: str) -> str:
    return "".join(ch.lower() for ch in name if ch.isalnum())


def _coerce_value_for_property(value: Any, prop_schema: Any) -> Any:
    if value is None:
        return value
    if not isinstance(prop_schema, dict):
        return value
    if _schema_accepts_array(prop_schema):
        return value if isinstance(value, list) else [value]
    return value


def _schema_accepts_array(schema: Dict[str, Any]) -> bool:
    if schema.get("type") == "array":
        return True
    for branch_key in ("anyOf", "oneOf"):
        branches = schema.get(branch_key)
        if isinstance(branches, list):
            for branch in branches:
                if isinstance(branch, dict) and branch.get("type") == "array":
                    return True
    return False
