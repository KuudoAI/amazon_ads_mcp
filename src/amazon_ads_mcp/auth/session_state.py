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

Token change detection:
- ``_last_seen_token_fingerprint_var`` tracks the SHA-256 fingerprint
  of the last refresh token seen in this session. Unlike other ContextVars,
  it is NOT cleared per-request — it persists across tool calls so the
  middleware can detect when a different tenant token arrives and invalidate
  stale identity/credential/profile state.
"""

import hashlib
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

# Session-scoped (NOT cleared per-request) — tracks which tenant token
# was last active so we can detect cross-tenant token swaps.
_last_seen_token_fingerprint_var: ContextVar[Optional[str]] = ContextVar(
    "last_seen_token_fingerprint", default=None
)

# Per-request: explains why tenant state was just cleared (or why
# state would not be session-sticky). Read by tool wrappers via
# ``compute_session_state`` to populate the ``state_reason`` field
# on responses. Set by ``RefreshTokenMiddleware`` on token swap and
# cleared in its ``finally`` block so it does not leak across
# requests.
_state_reset_reason_var: ContextVar[Optional[str]] = ContextVar(
    "state_reset_reason", default=None
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
# Accessors — token fingerprint (session-scoped, NOT cleared per-request)
# ---------------------------------------------------------------------------


def token_fingerprint(token: str) -> str:
    """Compute SHA-256 fingerprint for a refresh token.

    Consistent with ``OpenBridgeAuthProvider._token_fingerprint()`` so the
    same token produces the same digest everywhere.
    """
    return hashlib.sha256(token.encode()).hexdigest()


def get_last_seen_token_fingerprint() -> Optional[str]:
    """Return the fingerprint of the last refresh token seen in this session."""
    return _last_seen_token_fingerprint_var.get()


def set_last_seen_token_fingerprint(fingerprint: Optional[str]) -> None:
    """Set the fingerprint of the last refresh token seen in this session."""
    _last_seen_token_fingerprint_var.set(fingerprint)


# ---------------------------------------------------------------------------
# Accessors — state reset reason (per-request diagnostic for tool responses)
# ---------------------------------------------------------------------------


def get_state_reset_reason() -> Optional[str]:
    """Return the reason tenant state was just cleared, if any.

    Set by ``RefreshTokenMiddleware`` when it detects a mid-session
    token swap (value: ``"token_swapped"``) and cleared in the
    middleware's ``finally`` block. Tool wrappers read this via
    :func:`amazon_ads_mcp.middleware.auth_session_bridge.compute_session_state`
    to populate the ``state_reason`` response field so agent clients
    know they must re-establish context even though the transport
    is session-capable.
    """
    return _state_reset_reason_var.get()


def set_state_reset_reason(reason: Optional[str]) -> None:
    """Set (or clear) the per-request state reset reason."""
    _state_reset_reason_var.set(reason)


# ---------------------------------------------------------------------------
# Bulk reset — used in middleware cleanup and test fixtures
# ---------------------------------------------------------------------------


def reset_session_state() -> None:
    """Reset per-request ContextVars to ``None``.

    Call this in middleware ``finally`` blocks to prevent state
    leaking between requests.

    Note: ``_last_seen_token_fingerprint_var`` is intentionally
    NOT cleared here — it must survive across requests within the
    same session so the middleware can detect token swaps.
    Use ``reset_all_session_state()`` for full teardown (tests).
    """
    _active_identity_var.set(None)
    _active_credentials_var.set(None)
    _active_profiles_var.set(None)
    _refresh_token_override_var.set(None)
    _state_reset_reason_var.set(None)


def reset_all_session_state() -> None:
    """Reset ALL ContextVars including session-scoped fingerprint.

    Use in test fixtures for complete isolation between tests.
    Production code should use ``reset_session_state()`` instead.
    """
    reset_session_state()
    _last_seen_token_fingerprint_var.set(None)
