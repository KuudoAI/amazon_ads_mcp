"""Pre-flight JSON Schema validation middleware (Phase 1, SP-6/9/13 mirror).

Cross-server parity with
``amazon_sp_mcp/src/amazon_sp_mcp/middleware/schema_validation.py``.
Both servers must emit the same envelope ``error_code`` for the same
schema-violation shape. The conformance test in openbridge-mcp asserts
that property by sending matching bad-input shapes to both and checking
the codes line up.

Sits AFTER ``SchemaKeyNormalizationMiddleware`` and BEFORE FastMCP
dispatch in the Ads middleware chain. Validates the post-normalization
arg dict against the tool's published JSON Schema using
``jsonschema.Draft202012Validator`` and raises
:class:`amazon_ads_mcp.exceptions.ValidationError` carrying the canonical
``SCHEMA_*`` code (per
``openbridge-mcp/schemas/jsonschema_error_codes.json``) when a
constraint fails. The existing error envelope translator routes
``AdsValidationError`` to ``error_kind=mcp_input_validation``.
"""

from __future__ import annotations

import json
import logging
import pathlib
from types import MappingProxyType
from typing import Any, Awaitable, Callable, Dict, Mapping

from fastmcp.server.middleware import Middleware, MiddlewareContext
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError

from ..config.settings import settings
from ..exceptions import ValidationError as AdsValidationError

logger = logging.getLogger(__name__)


#: Canonical jsonschema validator → envelope error_code mapping.
#: Mirrors ``openbridge-mcp/schemas/jsonschema_error_codes.json`` and
#: stays byte-identical to the SP middleware's ERROR_CODE_MAP.
ERROR_CODE_MAP: Dict[str, str] = {
    "type": "SCHEMA_TYPE_MISMATCH",
    "required": "SCHEMA_REQUIRED",
    "maxItems": "SCHEMA_MAX_ITEMS",
    "minItems": "SCHEMA_MIN_ITEMS",
    "maxLength": "SCHEMA_MAX_LENGTH",
    "minLength": "SCHEMA_MIN_LENGTH",
    "maximum": "SCHEMA_MAXIMUM",
    "minimum": "SCHEMA_MINIMUM",
    "enum": "SCHEMA_ENUM_MISMATCH",
    "pattern": "SCHEMA_PATTERN_MISMATCH",
    "format": "SCHEMA_FORMAT_INVALID",
    "additionalProperties": "SCHEMA_ADDITIONAL_PROPERTIES",
    "oneOf": "SCHEMA_ONE_OF_FAILED",
    "anyOf": "SCHEMA_ANY_OF_FAILED",
    "allOf": "SCHEMA_ALL_OF_FAILED",
    "uniqueItems": "SCHEMA_UNIQUE_ITEMS",
    "const": "SCHEMA_CONST_MISMATCH",
    "multipleOf": "SCHEMA_MULTIPLE_OF",
}

FALLBACK_CODE = "SCHEMA_VALIDATION_FAILED"


# ---- Round 13 B-8: hint templates from canonical spec ------------------


def _load_hint_templates() -> Mapping[str, Dict[str, str]]:
    """Load and freeze the canonical jsonschema → hint-template map.

    Source of truth: ``openbridge-mcp/schemas/jsonschema_error_codes.json``
    (Round 11 spec). Parsed ONCE at module import time so per-request
    hint generation is template substitution only — zero file I/O on the
    hot path.

    Returns a ``MappingProxyType`` over a dict of
    ``error_code -> {"hint": "...", "summary_template": "..."}`` so
    callers cannot accidentally mutate the cache.

    Search order for the spec file (fail-open if none found — middleware
    falls back to generic boilerplate hints, never raises at import):

      1. ``OPENBRIDGE_SCHEMAS_DIR`` env var (deploy-time override)
      2. Packaged copy under ``amazon_ads_mcp/resources/contract/`` (prod
         containers — wheel-shipped copy is most reliable)
      3. Sibling ``openbridge-mcp/schemas/`` checkout (dev workstation)
    """
    import os

    candidates: list[pathlib.Path] = []
    env_dir = os.environ.get("OPENBRIDGE_SCHEMAS_DIR")
    if env_dir:
        candidates.append(pathlib.Path(env_dir) / "jsonschema_error_codes.json")
    here = pathlib.Path(__file__).resolve()
    # Packaged copy first — guaranteed present in production wheels.
    candidates.append(
        here.parent.parent
        / "resources"
        / "contract"
        / "jsonschema_error_codes.json"
    )
    # Workstation fallback: sibling openbridge-mcp checkout.
    # /Users/.../amazon_ads_mcp/src/amazon_ads_mcp/middleware/schema_validation.py
    # → ../../../../openbridge-mcp/schemas/jsonschema_error_codes.json
    candidates.append(
        here.parent.parent.parent.parent.parent
        / "openbridge-mcp"
        / "schemas"
        / "jsonschema_error_codes.json"
    )

    raw: Dict[str, Any] | None = None
    for path in candidates:
        try:
            if path.is_file():
                raw = json.loads(path.read_text(encoding="utf-8"))
                break
        except Exception:  # pragma: no cover - defensive
            continue
    if raw is None:
        return MappingProxyType({})

    out: Dict[str, Dict[str, str]] = {}
    mapping = raw.get("mapping", {}) or {}
    for _validator, entry in mapping.items():
        code = entry.get("error_code")
        if not isinstance(code, str):
            continue
        out[code] = {
            "hint": str(entry.get("hint") or ""),
            "summary_template": str(entry.get("summary_template") or ""),
        }
    fallback = raw.get("fallback") or {}
    fb_code = fallback.get("error_code")
    if isinstance(fb_code, str):
        out[fb_code] = {
            "hint": str(fallback.get("hint") or ""),
            "summary_template": str(fallback.get("summary_template") or ""),
        }
    # Freeze the inner dicts too — full-depth immutability.
    return MappingProxyType({k: MappingProxyType(v) for k, v in out.items()})


#: Frozen, process-lifetime template map. Hot path does dict lookups only.
_HINT_TEMPLATES: Mapping[str, Mapping[str, str]] = _load_hint_templates()


def _format_template(template: str, details: Dict[str, Any]) -> str:
    """Substitute ``{path}``, ``{limit}``, ``{actual}``, ``{allowed}``,
    ``{extra}``, ``{expected_type}``, ``{received_type}``, ``{format}``,
    ``{validator}`` from *details*. Missing keys render as the bracketed
    placeholder verbatim — callers see the gap rather than a crash."""
    if not template:
        return ""
    safe = {
        "path": details.get("field") or "",
        "limit": details.get("limit"),
        "actual": details.get("actual"),
        "allowed": ", ".join(str(x) for x in (details.get("allowed") or [])),
        "extra": details.get("extra") or "",
        "expected_type": details.get("expected_type") or "",
        "received_type": details.get("received_type") or "",
        "format": details.get("format") or "",
        "validator": details.get("validator") or "",
    }
    try:
        return template.format(**safe)
    except (KeyError, IndexError):  # pragma: no cover - defensive
        return template


def _hints_for_schema_error(code: str, details: Dict[str, Any]) -> list[str]:
    """Build the ``hints[]`` list for a schema-rejection envelope.

    Sources the primary hint from the canonical template map (parsed
    once at import time), then appends a single boilerplate fallback so
    even unrecognized codes carry SOMETHING actionable.

    Round 13 C-pre: for ``SCHEMA_ADDITIONAL_PROPERTIES`` (an unknown
    top-level field), consult the v1 report-fields catalog for
    did-you-mean candidates. Closes the gap where the catalog's 700+
    valid field_ids and display-label index sat unused while the
    rejection path emitted a generic boilerplate hint.
    """
    out: list[str] = []
    entry = _HINT_TEMPLATES.get(code) or _HINT_TEMPLATES.get(FALLBACK_CODE)
    if entry:
        primary = _format_template(entry.get("hint") or "", details)
        if primary:
            out.append(primary)
    if code == "SCHEMA_ADDITIONAL_PROPERTIES":
        # Round 13 follow-up: walk EVERY extra (jsonschema's plural
        # form ``'foo', 'bar' were unexpected`` packs multiple in one
        # error). The earlier code keyed off ``details.extra`` only
        # — when ``extras`` was multi-valued, just the first key got
        # the deprecated-shape lookup, and when the extractor
        # returned empty the lookup keyed off ``""``.
        extras: list[str] = list(details.get("extras") or [])
        if not extras and details.get("extra"):
            extras = [details.get("extra")]
        bad_field_fallback = details.get("field") or ""
        if not extras and bad_field_fallback:
            extras = [bad_field_fallback]
        tool_name = details.get("tool_name") or ""

        # Round 13 Phase C-1: deprecated-shape table FIRST for
        # CreateReport calls so v3-tutorial reflexes get the
        # actionable rewrite guidance ahead of generic suggestions.
        # Emit one hint per matched key when multiple v3-shape keys
        # arrive together.
        if "CreateReport" in tool_name and extras:
            try:
                from ..tools.report_fields_v1_handler import (
                    DEPRECATED_V1_SHAPE_KEYS,
                )

                for bad in extras:
                    dep_hint = DEPRECATED_V1_SHAPE_KEYS.get(bad)
                    if dep_hint and dep_hint not in out:
                        out.append(dep_hint)
            except Exception:  # pragma: no cover - defensive
                pass

        # Catalog-driven did-you-mean per remaining unmapped extra.
        if extras:
            try:
                from ..tools.report_fields_v1_handler import (
                    catalog_suggestions_for,
                )

                sugg_lines: list[str] = []
                for bad in extras[:5]:
                    s = catalog_suggestions_for(bad)
                    if s:
                        sugg_lines.append(f"{bad} → {', '.join(s)}")
                if sugg_lines:
                    out.append(
                        f"Did you mean: {'; '.join(sugg_lines)}? "
                        f"(matched against the v1 report-fields catalog)"
                    )
            except Exception:  # pragma: no cover - defensive
                pass
    # Always include the generic safety net so old clients that scan
    # for "input schema" still find guidance.
    out.append("Check required fields and input types in the tool schema.")
    return out


def _pointer_path(error: JsonSchemaValidationError) -> str:
    parts = [str(p) for p in error.absolute_path]
    return "/".join(parts)


def _required_field_name(error: JsonSchemaValidationError) -> str:
    msg = error.message or ""
    if msg.startswith("'") and "'" in msg[1:]:
        end = msg.index("'", 1)
        return msg[1:end]
    return ""


def _additional_property_name(error: JsonSchemaValidationError) -> str:
    """Return the FIRST offending extra-property name from a jsonschema
    ``additionalProperties: false`` rejection. For multi-extra cases
    use :func:`_additional_property_names` instead."""
    names = _additional_property_names(error)
    return names[0] if names else ""


def _additional_property_names(error: JsonSchemaValidationError) -> list[str]:
    """Return ALL offending extra-property names from a jsonschema
    ``additionalProperties: false`` rejection.

    jsonschema produces TWO message shapes:

      - Singular: ``"Additional properties are not allowed ('foo' was
        unexpected)"`` — one extra key per error.
      - Plural: ``"Additional properties are not allowed ('foo',
        'bar', 'baz' were unexpected)"`` — multiple extra keys in one
        error, common when the caller sends several v3 reflexes at
        once (``name`` + ``configuration`` + ``query``).

    Round 13 follow-up: the original singular-only regex returned
    empty for plural messages, leaking ``"Remove unknown key  or
    check schema for typos."`` (double space) and silently skipping
    the deprecated-shape hint enricher. This walker handles both
    forms and returns every quoted name in source order.
    """
    import re

    msg = error.message or ""
    if "are not allowed" not in msg or (
        "was unexpected" not in msg and "were unexpected" not in msg
    ):
        return []
    # Pull every single-quoted token in the message. Robust against
    # singular ("'foo' was") and plural ("'foo', 'bar', 'baz' were")
    # phrasings. The regex matches non-quote characters between
    # straight single quotes.
    return re.findall(r"'([^']+)'", msg)


def _build_details(error: JsonSchemaValidationError, code: str) -> Dict[str, Any]:
    details: Dict[str, Any] = {"code": code}
    field = _pointer_path(error)
    if code == "SCHEMA_REQUIRED":
        missing = _required_field_name(error)
        if missing:
            field = missing
            details["field"] = missing
        else:
            details["field"] = field
    elif code == "SCHEMA_ADDITIONAL_PROPERTIES":
        extras = _additional_property_names(error)
        if extras:
            # ``extra`` keeps the first key for the legacy hint
            # template ``Remove unknown key {extra} or check schema
            # for typos.`` The plural form is exposed as
            # ``extras`` so the hint enricher can emit one
            # deprecated-shape hint per matched key.
            details["extra"] = extras[0]
            details["extras"] = extras
        details["field"] = field
    else:
        details["field"] = field

    if code == "SCHEMA_MAX_ITEMS":
        if isinstance(error.validator_value, int):
            details["limit"] = error.validator_value
        if isinstance(error.instance, list):
            details["actual"] = len(error.instance)
    elif code == "SCHEMA_MIN_ITEMS":
        if isinstance(error.validator_value, int):
            details["limit"] = error.validator_value
        if isinstance(error.instance, list):
            details["actual"] = len(error.instance)
    elif code == "SCHEMA_MAX_LENGTH" or code == "SCHEMA_MIN_LENGTH":
        if isinstance(error.validator_value, int):
            details["limit"] = error.validator_value
    elif code == "SCHEMA_MAXIMUM" or code == "SCHEMA_MINIMUM":
        details["limit"] = error.validator_value
    elif code == "SCHEMA_ENUM_MISMATCH":
        if isinstance(error.validator_value, list):
            details["allowed"] = list(error.validator_value)
    elif code == "SCHEMA_TYPE_MISMATCH":
        details["expected_type"] = error.validator_value
        details["received_type"] = type(error.instance).__name__

    return details


def _exception_for(
    error: JsonSchemaValidationError,
    *,
    tool_name: str | None = None,
) -> AdsValidationError:
    validator = str(getattr(error, "validator", "") or "")
    code = ERROR_CODE_MAP.get(validator, FALLBACK_CODE)
    details = _build_details(error, code)
    # Round 13 B-8: populate hints from canonical template spec.
    # The error envelope translator surfaces `details["hints"]` under
    # the envelope's `hints[]` array (Ads error_envelope.py:444-448).
    if validator and FALLBACK_CODE == code:
        # Surface the original validator name in the fallback hint.
        details.setdefault("validator", validator)
    # Round 13 Phase C-1: thread tool_name so the hint enricher can
    # apply CreateReport-specific deprecated-shape guidance.
    if tool_name:
        details["tool_name"] = tool_name
    details["hints"] = _hints_for_schema_error(code, details)
    # Don't leak the tool_name back to envelope details surface — it's
    # purely a hint-enricher hook.
    details.pop("tool_name", None)
    field = details.get("field") or ""
    message = error.message or "Schema validation failed."
    exc = AdsValidationError(message=message, field=field)
    exc.code = code
    exc.details = details
    return exc


class SchemaValidationMiddleware(Middleware):
    """Run JSON Schema validation against the tool's input schema (Ads parity).

    Behavior is byte-identical to the SP middleware of the same name.
    """

    def __init__(self) -> None:
        self._tool_schema_cache: Dict[str, Any] = {}

    async def _get_tool_parameters(
        self, tool_name: str, fastmcp_context: Any
    ) -> Dict[str, Any] | None:
        cached = self._tool_schema_cache.get(tool_name)
        if cached is not None:
            return cached if cached else None
        tool = None
        try:
            fastmcp_server = getattr(fastmcp_context, "fastmcp", None)
            if fastmcp_server is None:
                return None
            tool = await fastmcp_server.get_tool(tool_name)
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug(
                "SchemaValidationMiddleware: get_tool(%s) raised %s",
                tool_name,
                exc,
            )
            return None
        if tool is None:
            self._tool_schema_cache[tool_name] = {}
            return None
        params = getattr(tool, "parameters", None)
        if not isinstance(params, dict):
            self._tool_schema_cache[tool_name] = {}
            return None
        self._tool_schema_cache[tool_name] = params
        return params

    @staticmethod
    def _alias_source_keys(tool_name: str) -> set[str]:
        """Pull the sidecar's registered arg_aliases ``from`` keys for
        *tool_name*. These are legitimate alias source keys that the
        sidecar's ADDITIVE rewrite leaves in place alongside the canonical
        target — strict-unknown must not reject them.

        Returns an empty set when no sidecar middleware is active or no
        aliases are registered for this tool. Defensive against import
        cycles and runtime singleton being unset.
        """
        try:
            from ..server import sidecar_middleware as sm_mod
        except Exception:  # pragma: no cover - defensive
            return set()
        mw = getattr(sm_mod, "_ACTIVE_MIDDLEWARE", None)
        if mw is None:
            return set()
        getter = getattr(mw, "alias_sources_for", None)
        if not callable(getter):
            return set()
        try:
            sources = getter(tool_name) or set()
        except Exception:  # pragma: no cover - defensive
            return set()
        return set(sources) if isinstance(sources, (set, list, tuple)) else set()

    @staticmethod
    def _maybe_inject_strict_unknown(
        params: Dict[str, Any], *, alias_sources: set[str] | None = None
    ) -> Dict[str, Any]:
        """Round 12 SP-7 (Ads parity): when ``MCP_STRICT_UNKNOWN_FIELDS``
        is on AND the tool's schema is silent on ``additionalProperties``,
        return a per-call schema copy with ``additionalProperties: false``
        injected. Respects existing intent when the schema declares
        ``additionalProperties`` (boolean True/False or sub-schema dict).

        ``alias_sources`` is an exemption set: keys the sidecar's
        additive arg_aliases left in the call dict alongside their
        canonical targets. We add permissive property entries for each
        so the validator doesn't reject them under
        ``additionalProperties: false``.

        Note: Ads also runs an independent ``check_strict_unknown_fields``
        in ``schema_normalization.py``; this layer is the jsonschema
        equivalent. Both fail fast on unknown fields and return
        ``mcp_input_validation`` envelopes, just with different error
        codes (``UNKNOWN_FIELD`` vs ``SCHEMA_ADDITIONAL_PROPERTIES``).
        """
        if not settings.mcp_strict_unknown_fields:
            return params
        if "additionalProperties" in params:
            return params
        injected = dict(params)
        injected["additionalProperties"] = False
        if alias_sources:
            existing_props = injected.get("properties")
            if isinstance(existing_props, dict):
                merged_props = dict(existing_props)
                for src_key in alias_sources:
                    if src_key not in merged_props:
                        merged_props[src_key] = {}
                injected["properties"] = merged_props
        return injected

    async def on_call_tool(
        self,
        context: MiddlewareContext,
        call_next: Callable[[MiddlewareContext], Awaitable[Any]],
    ) -> Any:
        message = getattr(context, "message", None)
        tool_name = getattr(message, "name", None)
        if not tool_name:
            return await call_next(context)

        args: Dict[str, Any] = dict(getattr(message, "arguments", None) or {})
        fastmcp_ctx = getattr(context, "fastmcp_context", None) or context
        params = await self._get_tool_parameters(tool_name, fastmcp_ctx)
        if not params:
            return await call_next(context)
        properties = params.get("properties")
        if not isinstance(properties, dict) or not properties:
            return await call_next(context)

        alias_sources = self._alias_source_keys(tool_name)
        effective_params = self._maybe_inject_strict_unknown(
            params, alias_sources=alias_sources
        )
        validator = Draft202012Validator(effective_params)
        errors = sorted(
            validator.iter_errors(args),
            key=lambda e: list(e.absolute_path),
        )
        if errors:
            raise _exception_for(errors[0], tool_name=tool_name)

        return await call_next(context)


def create_schema_validation_middleware() -> SchemaValidationMiddleware:
    """Factory used by :class:`server.server_builder.ServerBuilder`."""
    return SchemaValidationMiddleware()
