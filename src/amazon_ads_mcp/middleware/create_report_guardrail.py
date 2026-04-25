"""Guardrail for ``allv1_AdsApiv1CreateReport`` filter values.

Scope: validates ``adProduct.value`` only today. Enum source is
``components.schemas.AdProduct.enum`` from the bundled spec at
``dist/openapi/resources/AdsAPIv1All.json`` (loaded via
:func:`amazon_ads_mcp.utils.openapi.load_bundled_spec`). Adding more fields
is a matter of extending :data:`FIELD_TO_SCHEMA` and ensuring each added
field's schema is a string enum — the walker and the error-shaping
logic don't need to change.

The filter walker handles the full ``oneOf(and|on)`` predicate tree and
fails open on unknown shapes (wrong-shape input produces no error, not a
rejection — the goal is UX, not brittleness).

**This guardrail does NOT fix the upstream SPONSORED_PRODUCTS → Sponsored
Brands leakage.** A value that passes the enum check here can still hit the
upstream leak. That's a separate ticket tracked against the Ads API team.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, List, Optional, Set

from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import Middleware, MiddlewareContext

from ..utils.openapi import load_bundled_spec

logger = logging.getLogger(__name__)


# The operationId that surfaces as the mounted FastMCP tool name.
TARGET_TOOL_NAME = "allv1_AdsApiv1CreateReport"

# Mapping: filter ``field`` name → OpenAPI schema name whose ``enum`` lists
# accepted values. Extend as needed; every added schema must be a plain
# string enum for this guardrail to work unchanged.
FIELD_TO_SCHEMA: Dict[str, str] = {
    "adProduct.value": "AdProduct",
}

# One-time cache per process.
_ENUM_CACHE: Dict[str, Set[str]] = {}


def _load_enum_from_schema(schema_name: str) -> Set[str]:
    """Return the string-enum set declared in
    ``components.schemas.<schema_name>`` of the bundled spec.

    Cached per-process on first call. Raises ``KeyError`` if the schema is
    absent or not a string enum — surfaces schema drift instead of silently
    failing open.
    """
    if schema_name in _ENUM_CACHE:
        return _ENUM_CACHE[schema_name]
    spec = load_bundled_spec("AdsAPIv1All")
    schema = spec["components"]["schemas"][schema_name]
    values = schema.get("enum")
    if not values or not isinstance(values, list):
        raise KeyError(
            f"schema {schema_name!r} in bundled spec has no string enum — "
            f"cannot enforce guardrail"
        )
    resolved = set(values)
    _ENUM_CACHE[schema_name] = resolved
    return resolved


def _load_ad_product_enum() -> Set[str]:
    """Public alias used by tests: the AdProduct enum set."""
    return _load_enum_from_schema("AdProduct")


# ---------- sync walker -----------------------------------------------------


def _walk_filter(
    node: Any, on_leaf: Callable[[Dict[str, Any]], None]
) -> None:
    """Recurse a ``reports[].query.filter`` tree and call *on_leaf* on each
    ``on`` leaf predicate.

    The real v1 filter shape is::

        filter ::= {"and": {"filters": [filter, ...]}} | {"on": ComparisonPredicate}

    Unknown shapes degrade to no-op (fail open).
    """
    if not isinstance(node, dict):
        return
    if "and" in node:
        children = node["and"].get("filters") if isinstance(node["and"], dict) else None
        if isinstance(children, list):
            for child in children:
                _walk_filter(child, on_leaf)
        return
    if "on" in node:
        predicate = node["on"]
        if isinstance(predicate, dict):
            on_leaf(predicate)
        return
    # Unknown shape — walker bails silently. Goal is UX; brittleness is worse.


def validate_create_report_body(body: Dict[str, Any]) -> None:
    """Check every ``on`` predicate in the body against :data:`FIELD_TO_SCHEMA`.

    Raises ``ValueError`` on the first field that references an enforced
    ``field`` with one or more out-of-enum values. The error message names the
    field, lists the bad values, and enumerates every accepted value so the
    agent can self-correct in one round.

    Does nothing when:
    - The body isn't a dict / has no reports.
    - A report has no ``filter``.
    - A leaf references a field we don't have enum data for.
    - The filter has an unrecognized shape (walker fails open).
    """
    if not isinstance(body, dict):
        return
    reports = body.get("reports")
    if not isinstance(reports, list):
        return

    errors: List[str] = []

    def _check(predicate: Dict[str, Any]) -> None:
        field = predicate.get("field")
        if not isinstance(field, str):
            return
        schema_name = FIELD_TO_SCHEMA.get(field)
        if schema_name is None:
            return  # Field not in our allowlist — pass through.
        values = predicate.get("values")
        if not isinstance(values, list):
            return
        try:
            accepted = _load_enum_from_schema(schema_name)
        except KeyError:
            logger.warning(
                "create_report_guardrail: enum for field=%s schema=%s unavailable — "
                "skipping validation",
                field,
                schema_name,
            )
            return
        bad = [v for v in values if v not in accepted]
        if bad:
            errors.append(
                "filter field {field!r} received invalid value(s) "
                "{bad!r}; accepted values are {accepted!r}".format(
                    field=field,
                    bad=bad,
                    accepted=sorted(accepted),
                )
            )

    for report in reports:
        if not isinstance(report, dict):
            continue
        query = report.get("query")
        if not isinstance(query, dict):
            continue
        filter_node = query.get("filter")
        if filter_node is None:
            continue
        _walk_filter(filter_node, _check)

    if errors:
        # One ValueError surfaces every violation so the agent fixes them in
        # one round-trip. Join with "; " so error readers can parse individual
        # reports.
        raise ValueError("; ".join(errors))


# ---------- async middleware adapter ----------------------------------------


class CreateReportFilterGuardrailMiddleware(Middleware):
    """FastMCP middleware adapter: routes on the target tool name, calls the
    sync validator, surfaces ``ValueError`` as ``ToolError``.

    Sync/async boundary kept explicit: the walker and enum lookup are pure CPU
    and live on the sync side; the async boundary exists purely because
    FastMCP's middleware contract is a coroutine handler. Future refactors
    should NOT slide I/O into the walker.
    """

    async def on_call_tool(
        self, context: MiddlewareContext, call_next: Callable
    ):
        message = getattr(context, "message", None)
        tool_name: Optional[str] = getattr(message, "name", None) if message else None

        if tool_name != TARGET_TOOL_NAME:
            return await call_next(context)

        arguments = getattr(message, "arguments", None) or {}
        # The mounted tool accepts the request body under ``body`` (OpenAPI
        # request-body param). If the tool surface ever renames this, the
        # guardrail silently becomes a no-op — that's a fail-open stance on
        # shape drift; tests should catch the rename.
        body = arguments.get("body") if isinstance(arguments, dict) else None
        if body is None:
            return await call_next(context)

        try:
            validate_create_report_body(body)
        except ValueError as exc:
            raise ToolError(f"Invalid CreateReport body: {exc}") from exc

        return await call_next(context)
