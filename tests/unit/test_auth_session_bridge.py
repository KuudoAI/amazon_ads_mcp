from datetime import datetime, timedelta, timezone

import pytest

from amazon_ads_mcp.auth.session_state import (
    get_active_identity,
    reset_all_session_state,
    set_active_credentials,
    set_active_identity,
    set_active_profiles,
    set_last_seen_token_fingerprint,
)
from amazon_ads_mcp.middleware.auth_session_bridge import (
    AUTH_SESSION_STATE_KEY,
    hydrate_auth_from_mcp_session,
    persist_auth_to_mcp_session,
)
from amazon_ads_mcp.models import AuthCredentials, Identity


class DummyFastMCPContext:
    def __init__(self, with_session: bool = True):
        self.request_context = object() if with_session else None
        self._state = {}

    async def get_state(self, key):
        return self._state.get(key)

    async def set_state(self, key, value):
        self._state[key] = value


@pytest.mark.asyncio
async def test_hydrate_auth_from_session_state():
    reset_all_session_state()
    ctx = DummyFastMCPContext(with_session=True)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=30)
    ctx._state[AUTH_SESSION_STATE_KEY] = {
        "active_identity": {"id": "id-1", "type": "openbridge", "attributes": {}},
        "active_credentials": {
            "identity_id": "id-1",
            "access_token": "access-token",
            "token_type": "Bearer",
            "expires_at": expires_at.isoformat(),
            "base_url": "https://example.com",
            "headers": {"Authorization": "Bearer access-token"},
        },
        "active_profiles": {"id-1": "profile-1"},
        "last_seen_token_fingerprint": "fp-123",
    }

    await hydrate_auth_from_mcp_session(ctx)

    identity = get_active_identity()
    assert identity is not None
    assert identity.id == "id-1"
    reset_all_session_state()


@pytest.mark.asyncio
async def test_persist_auth_to_session_state():
    reset_all_session_state()
    ctx = DummyFastMCPContext(with_session=True)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)

    set_active_identity(Identity(id="id-2", type="openbridge", attributes={}))
    set_active_credentials(
        AuthCredentials(
            identity_id="id-2",
            access_token="token-2",
            expires_at=expires_at,
            base_url="https://api.example.com",
            headers={"x-test": "ok"},
        )
    )
    set_active_profiles({"id-2": "profile-2"})
    set_last_seen_token_fingerprint("fp-456")

    await persist_auth_to_mcp_session(ctx)

    state = ctx._state[AUTH_SESSION_STATE_KEY]
    assert state["active_identity"]["id"] == "id-2"
    assert state["active_credentials"]["identity_id"] == "id-2"
    assert state["active_profiles"] == {"id-2": "profile-2"}
    assert state["last_seen_token_fingerprint"] == "fp-456"
    reset_all_session_state()


@pytest.mark.asyncio
async def test_hydrate_persist_no_session_noop():
    reset_all_session_state()
    ctx = DummyFastMCPContext(with_session=False)

    await hydrate_auth_from_mcp_session(ctx)
    await persist_auth_to_mcp_session(ctx)

    assert AUTH_SESSION_STATE_KEY not in ctx._state
    reset_all_session_state()
