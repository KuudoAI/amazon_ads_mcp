"""``tool_name`` attribution for metering dimensions (Task 22 ruling #5).

No ``tool-name`` ContextVar existed anywhere in this repo before this
module (verified repo fact) -- every OTHER per-request ContextVar lives
next to the state it tracks (``_REGION_OVERRIDE_VAR``/``_ROUTING_STATE_VAR``
in ``utils/http_client.py``, the auth ContextVars in
``auth/session_state.py``). ``tool_name`` is metering-specific (it exists
only to become a ``usage_context()`` dimension), so it lives here instead.

Two call sites set/reset it around a dispatch, both using
:func:`tool_name_scope` for identical semantics:

1. :class:`ToolAttributionMiddleware`, registered in
   ``ServerBuilder._setup_middleware`` alongside the server's other
   middleware -- covers the ordinary ``on_call_tool`` dispatch path.
2. ``server/code_mode.py``'s ``bridged_call_tool`` -- the Code Mode sandbox
   bridge that calls tools *without* going through the server's middleware
   chain (design §7.1's attribution gap). Without this second call site,
   every Code Mode tool call would silently lose the ``tool_name``
   dimension even though the underlying HTTP call is metered exactly the
   same as an ordinary call.

Per ruling #5: "Missing attribution must never suppress an event (it's
just a dimension)" -- this module never raises, and a call made outside
either scope simply sees ``get_tool_name() is None``, which
``metering.context.usage_context()`` reflects as a ``None`` dimension
value, not a dropped event (`MeteredAsyncTransport`'s own failure
isolation guarantees that independently -- see the producer's
``transport.py`` module docstring).
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Awaitable, Callable, Iterator, Optional

from fastmcp.server.middleware import Middleware, MiddlewareContext

__all__ = ["ToolAttributionMiddleware", "get_tool_name", "tool_name_scope"]

_tool_name_var: ContextVar[Optional[str]] = ContextVar("metering_tool_name", default=None)


def get_tool_name() -> Optional[str]:
    """The tool name attributed to the current async context, or ``None``
    when no :func:`tool_name_scope` is active (e.g. a request outside any
    tool call, or attribution genuinely missing)."""
    return _tool_name_var.get()


@contextmanager
def tool_name_scope(name: Optional[str]) -> Iterator[None]:
    """Set ``tool_name`` for the duration of the ``with`` block and reset
    it in a ``finally`` -- used identically by
    :class:`ToolAttributionMiddleware` and ``code_mode.py``'s
    ``bridged_call_tool`` so both attribution call sites share one
    set/reset implementation."""
    token = _tool_name_var.set(name)
    try:
        yield
    finally:
        _tool_name_var.reset(token)


class ToolAttributionMiddleware(Middleware):
    """FastMCP middleware: sets ``tool_name`` for the duration of an
    ordinary ``on_call_tool`` dispatch. Registered in
    ``ServerBuilder._setup_middleware`` alongside the server's existing
    middleware -- position in the chain does not matter for correctness
    (every middleware wraps ``call_next``, and the eventual HTTP call
    happens deep inside that chain, still within the same async context),
    only that it wraps the dispatch at all.
    """

    async def on_call_tool(
        self,
        context: MiddlewareContext,
        call_next: Callable[[MiddlewareContext], Awaitable[Any]],
    ) -> Any:
        tool_name = getattr(context.message, "name", None) if context.message else None
        with tool_name_scope(tool_name):
            return await call_next(context)
