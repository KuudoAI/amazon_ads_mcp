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


async def check_strict_unknown_fields(
    tool_name: str,
    args: Optional[Dict[str, Any]],
    *,
    server: Any | None = None,
    fastmcp_context: Any | None = None,
    extra_known_fields: Optional[set] = None,
) -> None:
    """Raise :class:`ValidationError` if ``args`` contains keys not in the
    tool's schema. Run AFTER schema-key normalization AND sidecar alias
    rewrites, so legitimate aliases (e.g. ``reportId`` → ``reportIds``)
    survive — only fields that are still unknown after both passes are
    rejected.

    ``extra_known_fields`` lets callers (typically the sidecar middleware)
    pass an additional allowlist of legal field names — used to exempt
    sidecar's additive ``arg_aliases`` source keys, which sit in args
    alongside the canonical key after the rewrite.

    No-op when ``MCP_STRICT_UNKNOWN_FIELDS`` is false (opt-out) or when
    the tool has no resolvable schema. Default ON. Generates
    ``did_you_mean`` hints via ``difflib.get_close_matches`` against the
    schema's known properties.
    """
    if not settings.mcp_strict_unknown_fields:
        return
    if not args:
        return

    properties = await _get_tool_properties(
        tool_name, server=server, fastmcp_context=fastmcp_context
    )
    if not properties:
        # No schema to validate against — can't be strict
        return

    known = set(properties.keys())
    if extra_known_fields:
        known = known | set(extra_known_fields)
    unknown = [k for k in args.keys() if k not in known]
    if not unknown:
        return

    from difflib import get_close_matches

    from ..utils.errors import ValidationError

    hints = []
    for field in unknown:
        suggestions = get_close_matches(field, list(known), n=3, cutoff=0.5)
        hint = {"kind": "did_you_mean", "field": field}
        if suggestions:
            hint["suggestions"] = suggestions
        hints.append(hint)

    err = ValidationError(
        f"Unknown field(s) in tool {tool_name!r}: {sorted(unknown)}. "
        f"Set MCP_STRICT_UNKNOWN_FIELDS=false to allow pass-through.",
        field=unknown[0] if len(unknown) == 1 else None,
    )
    err.details["error_code"] = "UNKNOWN_FIELD"
    err.details["unknown_fields"] = sorted(unknown)
    if hints:
        err.details["hints"] = hints
    raise err


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


async def _get_tool_input_schema(
    tool_name: str,
    *,
    server: Any | None = None,
    fastmcp_context: Any | None = None,
) -> Dict[str, Any]:
    """Resolve the tool's FULL input schema (with ``type``, ``required``,
    etc.) from the FastMCP server. Sibling of ``_get_tool_properties``
    which returns only the inner ``properties`` dict.

    Returns ``{}`` (empty schema) when the tool has no resolvable schema —
    callers should treat this as "skip validation, no schema to check
    against" per the fail-open contract.
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
    return params


def _format_jsonschema_path(path) -> str:
    """Format a jsonschema error ``path`` deque as ``a.b[0].c``.

    String elements join with dots; integer elements use bracket notation
    so callers can distinguish array indices from property names. Empty
    path → empty string (top-level error).
    """
    parts: List[str] = []
    for elem in path:
        if isinstance(elem, int):
            parts.append(f"[{elem}]")
        else:
            if parts:
                parts.append(f".{elem}")
            else:
                parts.append(str(elem))
    return "".join(parts)


async def check_schema_constraints(
    tool_name: str,
    args: Optional[Dict[str, Any]],
    *,
    server: Any | None = None,
    fastmcp_context: Any | None = None,
    extra_known_fields: Optional[set] = None,
) -> None:
    """Run jsonschema validation against the tool's input schema, raising
    :class:`ValidationError` on any constraint violation (type, enum,
    required, numeric/array bounds).

    This is the dispatcher-level pre-flight check that closes the
    "schema-violations round-trip to Amazon" footgun. Runs AFTER
    schema-key normalization and sidecar alias rewrites, BEFORE
    ``check_strict_unknown_fields`` and tool dispatch.

    ``extra_known_fields`` exempts caller-known additional property names
    from the additionalProperties enforcement (used by sidecar middleware
    to allow ``arg_aliases`` source keys to survive — see
    ``alias_sources_for`` in ``server/sidecar_middleware.py``).

    Behavior:
    - Default ON via ``MCP_SCHEMA_CONSTRAINT_VALIDATION_ENABLED``
    - Multi-error: surfaces ALL violations in ``details["violations"]`` so
      callers can fix everything in one round-trip
    - Path format: ``a.b[0].c`` (dotted keys, bracketed indices)
    - additionalProperties enforced by the validator regardless of whether
      the schema declares it (most $ref-using schemas don't)
    - Fails OPEN on schema-lookup errors (logs telemetry, doesn't break
      tool execution) — see feedback_fail_open_telemetry.md
    """
    if not settings.mcp_schema_constraint_validation_enabled:
        return
    if args is None:
        args = {}

    try:
        schema = await _get_tool_input_schema(
            tool_name, server=server, fastmcp_context=fastmcp_context
        )
    except Exception as exc:
        # Fail-open: a schema-lookup failure must NOT break tool execution.
        # Log telemetry so operators can spot drift.
        logger.warning(
            "schema_lookup_failed for tool=%s error_type=%s error=%s",
            tool_name,
            type(exc).__name__,
            exc,
        )
        return

    if not schema or not isinstance(schema, dict):
        return

    # Lazy import — jsonschema is a declared dep but heavy enough we don't
    # want it loaded just for the module-import path.
    try:
        from jsonschema import Draft202012Validator
        from jsonschema import ValidationError as _JSValidationError
    except Exception as exc:  # pragma: no cover - jsonschema is a hard dep
        logger.warning(
            "jsonschema unavailable; skipping constraint validation: %s", exc
        )
        return

    # Strip additionalProperties from a SHALLOW copy of the schema so we
    # can enforce it ourselves with extra_known_fields applied. Most $ref
    # schemas don't declare it, but Pydantic-generated schemas often do
    # (model_config extra="forbid"); without stripping, the validator
    # would reject sidecar alias source keys before our exemption applies.
    schema_for_validator = dict(schema)
    schema_for_validator.pop("additionalProperties", None)

    try:
        validator = Draft202012Validator(schema_for_validator)
        errors = list(validator.iter_errors(args))
    except Exception as exc:
        # Schema-build failure (e.g. unresolvable $ref). Fail-open.
        logger.warning(
            "schema_lookup_failed (validator-build) for tool=%s error_type=%s "
            "error=%s",
            tool_name,
            type(exc).__name__,
            exc,
        )
        return

    # Manual additionalProperties enforcement (always, regardless of whether
    # the schema declared it) so extra_known_fields exemptions apply uniformly.
    declared = set((schema.get("properties") or {}).keys())
    if extra_known_fields:
        declared |= set(extra_known_fields)
    for key in args.keys():
        if key not in declared:
            synthetic = _JSValidationError(
                f"Additional properties are not allowed ({key!r} was unexpected)",
                path=[key],
                validator="additionalProperties",
                validator_value=False,
            )
            errors.append(synthetic)

    if not errors:
        return

    # Translate jsonschema errors into the v1 envelope shape.
    from ..utils.errors import ValidationError

    violations = []
    for e in errors:
        violations.append(
            {
                "path": _format_jsonschema_path(e.absolute_path or e.path),
                "issue": e.message,
                "validator": e.validator,
            }
        )

    first = violations[0]
    summary_path = first["path"] or "<root>"
    err = ValidationError(
        f"Schema validation failed for tool {tool_name!r}: "
        f"{first['issue']} (path: {summary_path}). "
        f"{len(violations)} violation(s) total.",
        field=first["path"] or None,
    )
    err.details["error_code"] = "INPUT_VALIDATION_FAILED"
    err.details["violations"] = violations
    raise err


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
