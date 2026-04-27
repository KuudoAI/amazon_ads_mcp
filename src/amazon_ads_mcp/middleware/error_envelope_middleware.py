"""FastMCP middleware that wraps tool dispatch in the v1 error envelope.

The middleware sits at the **outermost** layer of the tool-call middleware
chain (registered first in ``server_builder.py``). It catches every
exception raised by downstream middleware and tools, translates it into the
v1 envelope shape via :mod:`amazon_ads_mcp.middleware.error_envelope`, and
re-raises as a ``ToolError`` carrying the envelope JSON.

Three subtleties:

1. **Idempotency** — if a downstream middleware already raised a
   ``ToolError`` whose body is a v1 envelope, this middleware passes it
   through unchanged (no double-wrap).
2. **Telemetry threading** — pre-flight normalization events captured by
   :mod:`amazon_ads_mcp.middleware.schema_normalization` are read from a
   ``ContextVar`` and surfaced in ``_meta.normalized``.
3. **Successful calls** are pass-through; the middleware adds no overhead
   on the happy path beyond ``await call_next(context)``.

See ``openbridge-mcp/CONTRACT.md`` for the canonical envelope shape.
"""

from __future__ import annotations

import logging
from typing import Any, Awaitable, Callable

from fastmcp.exceptions import NotFoundError as _FastMCPNotFoundError
from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import Middleware, MiddlewareContext

from .error_envelope import (
    build_envelope_from_exception,
    envelope_to_json,
    is_envelope_text,
)
from .schema_normalization import get_current_normalization_events

logger = logging.getLogger(__name__)


class ErrorEnvelopeMiddleware(Middleware):
    """Wrap tool calls in the v1 cross-server error envelope contract."""

    async def on_call_tool(
        self,
        context: MiddlewareContext,
        call_next: Callable[[MiddlewareContext], Awaitable[Any]],
    ) -> Any:
        try:
            return await call_next(context)
        except ToolError as exc:
            # Idempotency: if the inner code already raised an envelope-shaped
            # ToolError, do not re-wrap. This protects Code Mode and any
            # downstream code that constructed a v1 envelope itself.
            if is_envelope_text(str(exc)):
                raise
            envelope = self._build_envelope(exc, context)
            raise ToolError(envelope_to_json(envelope)) from exc
        except Exception as exc:
            envelope = self._build_envelope(exc, context)
            raise ToolError(envelope_to_json(envelope)) from exc

    def _build_envelope(self, exc: BaseException, context: Any) -> dict[str, Any]:
        tool_name = self._extract_tool_name(context)
        normalized = get_current_normalization_events()
        return build_envelope_from_exception(
            exc,
            tool_name=tool_name,
            normalized=normalized,
        )

    @staticmethod
    def _is_not_found_like(exc: BaseException) -> bool:
        """True for ``NotFoundError`` directly OR a transformed ``McpError``
        that wraps one (FastMCP's ``ErrorHandlingMiddleware`` with
        ``transform_errors=True`` converts ``NotFoundError`` →
        ``McpError(code=-32001, ...)`` before our outermost middleware
        sees the exception). We accept both so the envelope wraps cleanly
        regardless of inner middleware choice."""
        if isinstance(exc, _FastMCPNotFoundError):
            return True
        # MCPError carries an ErrorData with a code attribute. -32001 is
        # the standard "Resource not found" / "Not found" code FastMCP
        # uses for transformed NotFoundError. -32002 is the resources
        # subtree variant per MCP spec.
        code = getattr(getattr(exc, "error", None), "code", None)
        if code in (-32001, -32002):
            return True
        cause = getattr(exc, "__cause__", None)
        if isinstance(cause, _FastMCPNotFoundError):
            return True
        return False

    async def on_get_prompt(
        self,
        context: MiddlewareContext,
        call_next: Callable[[MiddlewareContext], Awaitable[Any]],
    ) -> Any:
        """Round 12 follow-up: catch ``NotFoundError`` from the
        ``prompts/get`` JSON-RPC path and emit the same ``tool_not_found``
        envelope as ``on_call_tool``. Without this, prompt-name typos
        surface as bare JSON-RPC errors during client session warmup.

        Accepts both raw ``NotFoundError`` and the transformed
        ``McpError(-32001)`` produced by FastMCP's
        ``ErrorHandlingMiddleware`` (which sits inside this one).
        """
        try:
            return await call_next(context)
        except Exception as exc:
            if not self._is_not_found_like(exc):
                raise
            envelope = self._build_envelope(exc, context)
            raise ToolError(envelope_to_json(envelope)) from exc

    async def on_read_resource(
        self,
        context: MiddlewareContext,
        call_next: Callable[[MiddlewareContext], Awaitable[Any]],
    ) -> Any:
        """Mirror of ``on_get_prompt`` for ``resources/read``."""
        try:
            return await call_next(context)
        except Exception as exc:
            if not self._is_not_found_like(exc):
                raise
            envelope = self._build_envelope(exc, context)
            raise ToolError(envelope_to_json(envelope)) from exc

    @staticmethod
    def _extract_tool_name(context: Any) -> str | None:
        message = getattr(context, "message", None)
        if message is None:
            return None
        # Tool/prompt messages carry ``name``; resource messages carry ``uri``.
        name = getattr(message, "name", None)
        if name:
            return name
        uri = getattr(message, "uri", None)
        return str(uri) if uri else None


def create_error_envelope_middleware() -> ErrorEnvelopeMiddleware:
    """Factory mirroring the project's other ``create_*_middleware`` helpers."""
    return ErrorEnvelopeMiddleware()
