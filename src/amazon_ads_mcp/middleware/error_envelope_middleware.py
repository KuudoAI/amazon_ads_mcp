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
    def _extract_tool_name(context: Any) -> str | None:
        message = getattr(context, "message", None)
        if message is None:
            return None
        return getattr(message, "name", None)


def create_error_envelope_middleware() -> ErrorEnvelopeMiddleware:
    """Factory mirroring the project's other ``create_*_middleware`` helpers."""
    return ErrorEnvelopeMiddleware()
