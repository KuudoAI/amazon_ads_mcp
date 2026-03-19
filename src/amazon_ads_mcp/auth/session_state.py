"""Per-request session state using ContextVars for async safety.

This module provides ContextVar-backed storage for mutable per-request
authentication state. By using ContextVars instead of singleton instance
variables, each concurrent MCP client gets its own isolated state —
preventing cross-client auth leakage.

The pattern mirrors existing ContextVar usage in the codebase:
- ``_REGION_OVERRIDE_VAR`` / ``_ROUTING_STATE_VAR`` in http_client.py
- ``jwt_token_var`` / ``jwt_claims_var`` in authentication.py

All defaults are ``None`` to avoid shared mutable state. The profiles
accessor returns an empty dict when the underlying var is ``None``.
"""

from contextvars import ContextVar
from typing import Dict, Optional

from ..models import AuthCredentials, Identity

# ---------------------------------------------------------------------------
# ContextVar declarations
# ---------------------------------------------------------------------------

_active_identity_var: ContextVar[Optional[Identity]] = ContextVar(
    "active_identity", default=None
)

_active_credentials_var: ContextVar[Optional[AuthCredentials]] = ContextVar(
    "active_credentials", default=None
)

_active_profiles_var: ContextVar[Optional[Dict[str, str]]] = ContextVar(
    "active_profiles", default=None
)

_refresh_token_override_var: ContextVar[Optional[str]] = ContextVar(
    "refresh_token_override", default=None
)

# ---------------------------------------------------------------------------
# Accessors — identity
# ---------------------------------------------------------------------------


def get_active_identity() -> Optional[Identity]:
    """Return the active identity for the current async context."""
    return _active_identity_var.get()


def set_active_identity(identity: Optional[Identity]) -> None:
    """Set (or clear) the active identity for the current async context."""
    _active_identity_var.set(identity)


# ---------------------------------------------------------------------------
# Accessors — credentials
# ---------------------------------------------------------------------------


def get_active_credentials() -> Optional[AuthCredentials]:
    """Return cached credentials for the current async context."""
    return _active_credentials_var.get()


def set_active_credentials(credentials: Optional[AuthCredentials]) -> None:
    """Set (or clear) cached credentials for the current async context."""
    _active_credentials_var.set(credentials)


# ---------------------------------------------------------------------------
# Accessors — profiles  (copy-on-write: callers must set_active_profiles()
#                         after mutation to propagate changes)
# ---------------------------------------------------------------------------


def get_active_profiles() -> Dict[str, str]:
    """Return the identity→profile mapping for the current async context.

    Returns a **copy** to enforce copy-on-write semantics. Callers
    must call ``set_active_profiles()`` to persist mutations.
    Returns an empty dict when no profiles have been set, avoiding
    shared mutable default pitfalls.
    """
    profiles = _active_profiles_var.get()
    return dict(profiles) if profiles is not None else {}


def set_active_profiles(profiles: Optional[Dict[str, str]]) -> None:
    """Replace the identity→profile mapping for the current async context.

    Always pass a **new** dict to ensure copy-on-write semantics::

        current = get_active_profiles()
        updated = {**current, identity_id: profile_id}
        set_active_profiles(updated)
    """
    _active_profiles_var.set(profiles)


# ---------------------------------------------------------------------------
# Accessors — refresh token override (OpenBridge per-request)
# ---------------------------------------------------------------------------


def get_refresh_token_override() -> Optional[str]:
    """Return the per-request refresh token override, if any."""
    return _refresh_token_override_var.get()


def set_refresh_token_override(token: Optional[str]) -> None:
    """Set (or clear) the per-request refresh token override."""
    _refresh_token_override_var.set(token)


# ---------------------------------------------------------------------------
# Bulk reset — used in middleware cleanup and test fixtures
# ---------------------------------------------------------------------------


def reset_session_state() -> None:
    """Reset all per-request ContextVars to ``None``.

    Call this in middleware ``finally`` blocks and test fixture
    teardown to prevent state leaking between requests or tests.
    """
    _active_identity_var.set(None)
    _active_credentials_var.set(None)
    _active_profiles_var.set(None)
    _refresh_token_override_var.set(None)
