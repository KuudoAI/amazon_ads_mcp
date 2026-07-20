"""The transport install seam (Task 22 ruling #3; fix round 1, CRITICAL +
IMPORTANT).

``install_metered_transport`` is called from exactly two places, both in
``AuthenticatedClient.__init__`` (``utils/http_client.py``), right after
``super().__init__(...)``: once on ``self._transport``, and once for every
populated value in ``self._mounts`` (proxy transports httpx auto-installs
from ``HTTP_PROXY``/``HTTPS_PROXY``/``ALL_PROXY`` when ``trust_env=True``,
httpx's default here -- verified no construction path in this repo
overrides ``trust_env``). httpx 0.28.1's ``Client._transport_for_url``
checks ``_mounts`` for a matching pattern FIRST and only falls back to
``self._transport`` when none matches, so a populated, unwrapped mount
would bypass metering entirely regardless of what wraps
``self._transport`` alone. Together these two calls cover every way an
``AuthenticatedClient`` (or a subclass, e.g. ``ResilientAuthenticatedClient``,
whose ``__init__`` calls ``super().__init__(*args, **kwargs)``) is ever
constructed: ``ServerBuilder._setup_http_client()`` (one shared instance
for all OpenAPI mounts) and ``HTTPClientManager.get_client(client_class=
AuthenticatedClient)`` (the secondary instance ``tools/profile_listing.py``
uses). Neither construction path -- nor anything else in this repo --
ever needs to call this function directly.

Fix round 1, CRITICAL: ``ServerBuilder.build()`` (which constructs the
shared ``AuthenticatedClient`` via ``_setup_http_client()``) runs BEFORE
``mcp.run()`` ever triggers ``server_lifespan()``, where
``start_metering()`` actually installs the active runtime. The original
design made the wrap decision ONCE, at ``__init__`` time -- for the
shared client, that decision permanently captured ``runtime=None``, so
the shared client (used for every OpenAPI-mounted tool call) was NEVER
metered in the real running server, no matter how long it ran afterward.
``LazyMeteredTransport`` fixes this by deferring the decision to REQUEST
time: it is installed unconditionally at construction, and every
``handle_async_request`` call freshly consults :func:`get_metering_runtime`
-- construction order relative to ``start_metering()``/``stop_metering()``
no longer matters at all.

This module deliberately imports NOTHING from ``mcp_outbound_metering``,
directly or via ``compat`` -- it only needs a duck-typed ``runtime`` object
exposing ``wrap_transport(...)`` (whatever :func:`set_metering_runtime`
was given), so it stays importable, at module scope, from
``utils/http_client.py`` on every Python version, including <3.12 where
metering is entirely unavailable. This is also why this module never
imports ``metering.context``/``metering.normalizer`` at module scope: both
of those import back from ``utils.http_client`` (``context.py`` needs
``get_routing_state``), and importing them eagerly here would create an
import cycle with ``utils/http_client.py`` (which imports this module at
ITS module scope). The lazy import inside ``LazyMeteredTransport``'s own
``handle_async_request`` below only ever runs once ``utils.http_client``
has finished executing (a request is being sent), by which point the
cycle is moot.
"""

from __future__ import annotations

from typing import Any, Optional

import httpx

__all__ = [
    "LazyMeteredTransport",
    "get_metering_runtime",
    "install_metered_transport",
    "set_metering_runtime",
]

_runtime: Optional[Any] = None


def set_metering_runtime(runtime: Optional[Any]) -> None:
    """Set (or clear, with ``None``) the process-wide active metering
    runtime. Called only by the lifespan wiring (``metering.lifespan``)
    and by tests -- never by application/tool code."""
    global _runtime
    _runtime = runtime


def get_metering_runtime() -> Optional[Any]:
    """The active metering runtime, or ``None`` when metering is disabled,
    unavailable, or not yet started."""
    return _runtime


class LazyMeteredTransport(httpx.AsyncBaseTransport):
    """Wraps ``inner`` and defers the metering-wrap decision to REQUEST
    time (fix round 1, CRITICAL) instead of construction time.

    Every ``handle_async_request`` call freshly reads
    :func:`get_metering_runtime`:

    - ``None`` (no active runtime -- metering disabled, unavailable, not
      yet started, or already stopped): delegates straight to ``inner``,
      unmetered.
    - An active runtime: builds the real wrapped transport via
      ``runtime.wrap_transport(inner, ...)`` ONCE per distinct runtime
      object (cached by identity in ``self._cached_runtime``/
      ``self._cached_transport`` -- rebuilt only if the active runtime
      object itself changes, e.g. after a stop/restart cycle installs a
      new instance) and delegates to that.

    This makes the wrap fully independent of construction order: a client
    built before ``start_metering()`` ever runs (the real boot order --
    ``ServerBuilder.build()`` constructs the shared client before
    ``mcp.run()`` triggers ``server_lifespan()``) still gets metered once
    a runtime activates, and correctly reverts to unmetered pass-through
    if the runtime later deactivates (``stop_metering()``) -- with no
    errors either way.

    ``aclose()`` closes ``inner`` exactly once. It never routes through
    the cached wrapped transport's own ``aclose()`` -- that would also
    close ``inner``, just redundantly (``MeteredAsyncTransport.aclose()``
    is itself idempotent, but there is no need to rely on that here, and
    the cached transport may be stale/absent if no runtime was ever
    active).
    """

    def __init__(self, inner: httpx.AsyncBaseTransport) -> None:
        self._inner = inner
        self._cached_runtime: Optional[Any] = None
        self._cached_transport: Optional[httpx.AsyncBaseTransport] = None
        self._closed = False

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        runtime = get_metering_runtime()
        if runtime is None:
            return await self._inner.handle_async_request(request)

        if runtime is not self._cached_runtime:
            from .context import tenant_key, usage_context
            from .normalizer import normalize_path

            self._cached_transport = runtime.wrap_transport(
                self._inner,
                context_provider=usage_context,
                tenant_key_provider=tenant_key,
                path_normalizer=normalize_path,
                template_resolver=None,
            )
            self._cached_runtime = runtime

        assert self._cached_transport is not None
        return await self._cached_transport.handle_async_request(request)

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        await self._inner.aclose()


def install_metered_transport(inner: httpx.AsyncBaseTransport) -> httpx.AsyncBaseTransport:
    """Always wrap ``inner`` in a :class:`LazyMeteredTransport` (fix round
    1, CRITICAL) -- the actual metering decision is deferred to request
    time inside that wrapper, never made here at construction time. Safe
    to call for both ``self._transport`` and any populated
    ``self._mounts`` value (fix round 1, IMPORTANT)."""
    return LazyMeteredTransport(inner)
