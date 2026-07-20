"""The transport install seam (Task 22 ruling #3).

``install_metered_transport`` is called from exactly one place in
production code: ``AuthenticatedClient.__init__``
(``utils/http_client.py``), right after ``super().__init__(...)``, wrapping
``self._transport``. httpx 0.28.1's ``AsyncClient`` dispatches every
request through ``self._transport`` unless ``self._mounts`` has a matching
pattern (verified: no construction path anywhere in this repo passes
``mounts=``, so ``_mounts`` is always empty and every request routes
through ``self._transport``) -- wrapping ``self._transport`` in
``__init__`` therefore covers every way an ``AuthenticatedClient`` (or a
subclass, e.g. ``ResilientAuthenticatedClient``, whose ``__init__`` calls
``super().__init__(*args, **kwargs)``) is ever constructed:
``ServerBuilder._setup_http_client()`` (one shared instance for all OpenAPI
mounts) and ``HTTPClientManager.get_client(client_class=AuthenticatedClient)``
(the secondary instance ``tools/profile_listing.py`` uses). Neither
construction path -- nor anything else in this repo -- ever needs to call
this function directly.

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
ITS module scope). The lazy import inside :func:`install_metered_transport`
below only ever runs once ``utils.http_client`` has finished executing (a
client is being constructed), by which point the cycle is moot.
"""

from __future__ import annotations

from typing import Any, Optional

import httpx

__all__ = ["get_metering_runtime", "install_metered_transport", "set_metering_runtime"]

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


def install_metered_transport(inner: httpx.AsyncBaseTransport) -> httpx.AsyncBaseTransport:
    """Wrap ``inner`` with the metered transport when a runtime is active;
    otherwise return ``inner`` UNCHANGED. Never wraps ``_mounts`` -- this
    function only ever touches the transport instance handed to it
    (``self._transport`` in ``AuthenticatedClient.__init__``), and
    ``_mounts`` is unused throughout this repo (see the module docstring).
    """
    runtime = get_metering_runtime()
    if runtime is None:
        return inner

    from .context import tenant_key, usage_context
    from .normalizer import normalize_path

    return runtime.wrap_transport(
        inner,
        context_provider=usage_context,
        tenant_key_provider=tenant_key,
        path_normalizer=normalize_path,
        template_resolver=None,
    )
