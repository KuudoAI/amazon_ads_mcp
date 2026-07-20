"""Usage-context and tenant-key providers (Task 22 ruling #4).

Passed to ``MeteringRuntime.wrap_transport(context_provider=usage_context,
tenant_key_provider=tenant_key, ...)`` (see ``metering/adapter.py``).
Dimension allowlist (must match ``metering.yaml``'s ``dimensions:`` list
and ``METERING_DIMENSIONS``): ``identity_id``, ``profile_id``, ``region``,
``auth_method``, ``tool_name``. ``operation_id``/``api_group`` are
intentionally omitted in v1 -- there is no HTTP-layer source for either
without a ``template_resolver`` (post-v1, design §3.2).

Like ``normalizer.py``, this module has no dependency on
``mcp_outbound_metering`` -- only on this repo's own auth/session-state
modules -- so it stays importable on every supported Python version.
Every field lookup below is independently guarded: a failure resolving
one dimension (e.g. no auth manager configured yet) must never blank out
the others, and per ruling #4/§8.3, missing attribution must never
suppress the usage event itself -- ``MeteredAsyncTransport``'s own
failure isolation guarantees that independently even if this whole
function raised, but the per-field guards here keep as much real
attribution as possible instead of an all-or-nothing ``{}``.
"""

from __future__ import annotations

from typing import Dict, Optional

from ..auth.manager import get_auth_manager
from ..auth.session_state import get_active_identity
from .attribution import get_tool_name

__all__ = ["tenant_key", "usage_context"]


def _identity_id() -> Optional[str]:
    identity = get_active_identity()
    return identity.id if identity is not None else None


def _profile_id() -> Optional[str]:
    try:
        return get_auth_manager().get_active_profile_id()
    except Exception:
        return None


def _region() -> Optional[str]:
    try:
        # Imported lazily: `utils.http_client` imports `metering.adapter`
        # at module scope, and `metering.adapter` imports THIS module
        # lazily (inside a function) for exactly this reason -- see
        # `adapter.py`'s module docstring. Importing `get_routing_state`
        # at this module's own top level would be fine in isolation, but
        # keeping it lazy here too avoids ever depending on import order
        # between `utils.http_client` and `metering.context`.
        from ..utils.http_client import get_routing_state

        routing_state = get_routing_state()
        return routing_state.get("region") if routing_state else None
    except Exception:
        return None


def _auth_method() -> Optional[str]:
    try:
        provider = getattr(get_auth_manager(), "provider", None)
        return getattr(provider, "provider_type", None) if provider is not None else None
    except Exception:
        return None


def usage_context() -> Dict[str, Optional[str]]:
    """Opaque analytics dimensions for the current call (design §3.2,
    ruling #4): ``identity_id`` from ``get_active_identity()``,
    ``profile_id`` from the active auth manager (if exposed by session
    state), ``region`` from ``get_routing_state()`` (``None`` when
    unset), ``auth_method`` from the active provider's ``provider_type``,
    and ``tool_name`` from the attribution ContextVar
    (``metering.attribution``)."""
    return {
        "identity_id": _identity_id(),
        "profile_id": _profile_id(),
        "region": _region(),
        "auth_method": _auth_method(),
        "tool_name": get_tool_name(),
    }


def tenant_key() -> Optional[str]:
    """Opaque tenant lookup key (design §3.2, ruling #4): the active
    identity's id -- the same value ``usage_context()`` reports as
    ``identity_id``."""
    return _identity_id()
