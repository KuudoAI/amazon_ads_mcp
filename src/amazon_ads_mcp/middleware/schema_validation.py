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

import logging
from typing import Any, Awaitable, Callable, Dict

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
    msg = error.message or ""
    if "(" in msg and "was unexpected" in msg:
        try:
            start = msg.index("'") + 1
            end = msg.index("'", start)
            return msg[start:end]
        except ValueError:
            return ""
    return ""


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
        extra = _additional_property_name(error)
        if extra:
            details["extra"] = extra
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


def _exception_for(error: JsonSchemaValidationError) -> AdsValidationError:
    validator = str(getattr(error, "validator", "") or "")
    code = ERROR_CODE_MAP.get(validator, FALLBACK_CODE)
    details = _build_details(error, code)
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
            raise _exception_for(errors[0])

        return await call_next(context)


def create_schema_validation_middleware() -> SchemaValidationMiddleware:
    """Factory used by :class:`server.server_builder.ServerBuilder`."""
    return SchemaValidationMiddleware()
