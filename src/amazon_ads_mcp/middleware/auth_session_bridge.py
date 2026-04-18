"""Shared auth session state bridge utilities.

These helpers synchronize auth ContextVars with FastMCP per-session state.
They are used by middleware and code-mode nested tool dispatch wrappers.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from ..auth.session_state import (
    get_active_credentials,
    get_active_identity,
    get_active_profiles,
    get_last_seen_token_fingerprint,
    set_active_credentials,
    set_active_identity,
    set_active_profiles,
    set_last_seen_token_fingerprint,
)
from ..models import AuthCredentials, Identity

logger = logging.getLogger(__name__)

# FastMCP per-session state key for auth context persistence across tool calls.
AUTH_SESSION_STATE_KEY = "amazon_ads_auth_session"


def has_auth_session(fastmcp_context: Any) -> bool:
    """Return True when the context has an active MCP session.

    FastMCP startup/introspection paths do not have a bound request_context.
    In those cases, get_state/set_state is unavailable and callers must no-op.
    """
    if not fastmcp_context:
        return False
    if not hasattr(fastmcp_context, "get_state"):
        return False
    if hasattr(fastmcp_context, "request_context"):
        if getattr(fastmcp_context, "request_context", None) is None:
            return False
    return True


async def hydrate_auth_from_mcp_session(
    fastmcp_context: Any, logger_instance: Optional[logging.Logger] = None
) -> None:
    """Hydrate auth ContextVars from FastMCP session state."""
    if not has_auth_session(fastmcp_context):
        return

    log = logger_instance or logger
    try:
        state = await fastmcp_context.get_state(AUTH_SESSION_STATE_KEY)
        if not state or not isinstance(state, dict):
            return

        identity_payload = state.get("active_identity")
        credentials_payload = state.get("active_credentials")
        profiles_payload = state.get("active_profiles")
        last_fp = state.get("last_seen_token_fingerprint")
        active_region = state.get("active_region")

        identity = (
            Identity.model_validate(identity_payload)
            if isinstance(identity_payload, dict)
            else None
        )
        credentials = (
            AuthCredentials.model_validate(credentials_payload)
            if isinstance(credentials_payload, dict)
            else None
        )

        profiles: Optional[Dict[str, str]] = None
        if isinstance(profiles_payload, dict):
            profiles = {str(key): str(value) for key, value in profiles_payload.items()}

        set_active_identity(identity)
        set_active_credentials(credentials)
        set_active_profiles(profiles)
        set_last_seen_token_fingerprint(last_fp if isinstance(last_fp, str) else None)

        # Region is provider-managed (not ContextVar). Restore when possible.
        if isinstance(active_region, str):
            try:
                from ..auth.manager import get_auth_manager

                auth_manager = get_auth_manager()
                provider = getattr(auth_manager, "provider", None)
                if provider and hasattr(provider, "_region"):
                    provider._region = active_region
            except Exception as region_exc:
                log.debug("Failed to hydrate active region: %s", region_exc)
    except Exception as exc:
        log.warning("Failed to hydrate auth session state: %s", exc)


async def persist_auth_to_mcp_session(
    fastmcp_context: Any, logger_instance: Optional[logging.Logger] = None
) -> None:
    """Persist auth ContextVars to FastMCP session state."""
    if not has_auth_session(fastmcp_context):
        return

    log = logger_instance or logger
    try:
        identity = get_active_identity()
        credentials = get_active_credentials()
        profiles = get_active_profiles()
        last_fp = get_last_seen_token_fingerprint()
        active_region: Optional[str] = None
        try:
            from ..auth.manager import get_auth_manager

            auth_manager = get_auth_manager()
            active_region = auth_manager.get_active_region()
        except Exception as region_exc:
            log.debug("Failed to persist active region: %s", region_exc)

        state = {
            "active_identity": identity.model_dump(mode="json") if identity else None,
            "active_credentials": (
                credentials.model_dump(mode="json") if credentials else None
            ),
            "active_profiles": profiles,
            "last_seen_token_fingerprint": last_fp,
            "active_region": active_region,
        }
        await fastmcp_context.set_state(AUTH_SESSION_STATE_KEY, state)
    except Exception as exc:
        log.warning("Failed to persist auth session state: %s", exc)
