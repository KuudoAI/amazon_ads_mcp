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
- ``_last_seen_token_fingerprint_var`` tracks a provider-appropriate
  fingerprint of the last tenant-scoping token seen in this session. Unlike
  other ContextVars, it is NOT cleared per-request — it persists across tool
  calls so middleware can detect when a different tenant token arrives and
  invalidate stale identity/credential/profile state. Kuudo supplies a
  provider-instance-keyed discriminator; raw API keys never enter this state.
- ``_request_token_fingerprint_var`` carries the current request's
  fingerprint across middleware ordering boundaries. Its owner must restore
  the returned ContextVar token in a ``finally`` block.
"""

import hashlib
from contextvars import ContextVar, Token as ContextToken
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

_request_token_fingerprint_var: ContextVar[Optional[str]] = ContextVar(
    "request_token_fingerprint", default=None
)

# Per-request: explains why tenant state was just cleared (or why
# state would not be session-sticky). Read by tool wrappers via
# ``compute_session_state`` to populate the ``state_reason`` field
# on responses. Set by tenant-token reconciliation on token swap and
# cleared by request auth middleware so it does not leak across requests.
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
    """Compute a SHA-256 fingerprint for a tenant-scoping token.

    Consistent with ``OpenBridgeAuthProvider._token_fingerprint()`` so the
    same token produces the same digest everywhere.
    """
    return hashlib.sha256(token.encode()).hexdigest()


def get_last_seen_token_fingerprint() -> Optional[str]:
    """Return the last tenant-token fingerprint seen in this session."""
    return _last_seen_token_fingerprint_var.get()


def set_last_seen_token_fingerprint(fingerprint: Optional[str]) -> None:
    """Set the last tenant-token fingerprint seen in this session."""
    _last_seen_token_fingerprint_var.set(fingerprint)


def bind_request_tenant_fingerprint(
    fingerprint: str,
) -> ContextToken[Optional[str]]:
    """Bind a tenant fingerprint to the current middleware context.

    The provider derives the discriminator before calling this function, so
    the raw tenant token never enters session persistence. Callers must pass
    the returned token to :func:`reset_request_tenant_token` in a ``finally``
    block.
    """
    return _request_token_fingerprint_var.set(fingerprint)


def reset_request_tenant_token(token: ContextToken[Optional[str]]) -> None:
    """Restore the previous request tenant-token fingerprint."""
    _request_token_fingerprint_var.reset(token)


def reconcile_request_tenant_state() -> bool:
    """Bind hydrated tenant state to the current request's token.

    Returns ``True`` when existing tenant state was cleared. State without a
    prior fingerprint is also cleared before binding: it may have been
    persisted by a version that did not fingerprint this provider's bearer,
    so preserving it would silently assign unknown credentials to the current
    caller.
    """
    new_fp = _request_token_fingerprint_var.get()
    if new_fp is None:
        return False

    return _reconcile_tenant_state(new_fp)


def reconcile_tenant_state_for_token(token: str) -> bool:
    """Reconcile hydrated tenant state against a raw request token."""
    return _reconcile_tenant_state(token_fingerprint(token))


def _reconcile_tenant_state(new_fp: str) -> bool:
    """Clear tenant state when ``new_fp`` does not own hydrated state."""

    previous_fp = get_last_seen_token_fingerprint()
    has_unbound_state = (
        get_active_identity() is not None
        or get_active_credentials() is not None
        or bool(get_active_profiles())
    )
    token_changed = previous_fp is not None and previous_fp != new_fp
    unbound_state = previous_fp is None and has_unbound_state

    if token_changed or unbound_state:
        set_active_identity(None)
        set_active_credentials(None)
        set_active_profiles(None)
        set_state_reset_reason("token_swapped")

    set_last_seen_token_fingerprint(new_fp)
    return token_changed or unbound_state


# ---------------------------------------------------------------------------
# Accessors — state reset reason (per-request diagnostic for tool responses)
# ---------------------------------------------------------------------------


def get_state_reset_reason() -> Optional[str]:
    """Return the reason tenant state was just cleared, if any.

    Set by tenant-token reconciliation when it detects a mid-session token
    swap (value: ``"token_swapped"``) and cleared by the request auth
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
    _request_token_fingerprint_var.set(None)
    _state_reset_reason_var.set(None)


def reset_hydrated_session_state() -> None:
    """Clear hydrated auth state while preserving current request binding.

    Session hydration uses this when no saved state exists or state loading
    fails. The request-token fingerprint may already have been bound by an
    outer authorization middleware and must remain available for
    reconciliation after hydration.
    """
    _active_identity_var.set(None)
    _active_credentials_var.set(None)
    _active_profiles_var.set(None)
    _refresh_token_override_var.set(None)
    _state_reset_reason_var.set(None)
    _last_seen_token_fingerprint_var.set(None)


def reset_all_session_state() -> None:
    """Reset ALL ContextVars including session-scoped fingerprint.

    Use in test fixtures for complete isolation between tests.
    Production code should use ``reset_session_state()`` instead.
    """
    reset_session_state()
    _last_seen_token_fingerprint_var.set(None)
