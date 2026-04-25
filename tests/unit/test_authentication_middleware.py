from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import jwt
import pytest

from amazon_ads_mcp.middleware.authentication import (
    AuthSessionStateMiddleware,
    AuthConfig,
    JWTAuthenticationMiddleware,
    RefreshTokenMiddleware,
)


class DummyRequest:
    def __init__(self, headers):
        self.headers = headers


class DummyRequestContext:
    def __init__(self, request):
        self.request = request


class DummyFastMCPContext:
    def __init__(self, headers):
        self.request_context = DummyRequestContext(DummyRequest(headers))


class DummyContext:
    def __init__(self, fastmcp_context):
        self.fastmcp_context = fastmcp_context
        self.message = None


class DummyStateFastMCPContext:
    def __init__(self, initial_state=None):
        self.session_id = "test-session"
        self.request_context = DummyRequestContext(DummyRequest({}))
        self._state = initial_state or {}

    async def get_state(self, key):
        return self._state.get(key)

    async def set_state(self, key, value):
        self._state[key] = value


def _make_token(payload):
    return jwt.encode(payload, "secret", algorithm="HS256")


@pytest.mark.asyncio
async def test_refresh_token_middleware_sets_contextvar():
    from amazon_ads_mcp.auth.session_state import get_refresh_token_override

    config = AuthConfig()
    config.enabled = False
    config.refresh_token_enabled = False

    provider = MagicMock()
    auth_manager = SimpleNamespace(provider=provider)
    middleware = RefreshTokenMiddleware(config, auth_manager)

    headers = {"authorization": "Bearer refresh-token"}
    ctx = DummyContext(DummyFastMCPContext(headers))

    captured = {}

    async def capturing_call_next(c):
        captured["token"] = get_refresh_token_override()
        return "ok"

    result = await middleware.on_request(ctx, capturing_call_next)

    assert result == "ok"
    assert captured["token"] == "refresh-token"
    # Provider singleton should NOT be mutated
    provider.set_refresh_token.assert_not_called()


@pytest.mark.asyncio
async def test_refresh_token_middleware_prefers_x_openbridge_token():
    """X-Openbridge-Token takes priority over Authorization Bearer."""
    from amazon_ads_mcp.auth.session_state import get_refresh_token_override

    config = AuthConfig()
    config.enabled = False
    config.refresh_token_enabled = False

    provider = MagicMock()
    auth_manager = SimpleNamespace(provider=provider)
    middleware = RefreshTokenMiddleware(config, auth_manager)

    headers = {
        "x-openbridge-token": "ob-token:secret123",
        "authorization": "Bearer should-not-be-used",
    }
    ctx = DummyContext(DummyFastMCPContext(headers))

    captured = {}

    async def capturing_call_next(c):
        captured["token"] = get_refresh_token_override()
        return "ok"

    result = await middleware.on_request(ctx, capturing_call_next)

    assert result == "ok"
    assert captured["token"] == "ob-token:secret123"


@pytest.mark.asyncio
async def test_refresh_token_middleware_reads_x_openbridge_token_without_bearer_prefix():
    """X-Openbridge-Token is a raw token, no Bearer prefix needed."""
    from amazon_ads_mcp.auth.session_state import get_refresh_token_override

    config = AuthConfig()
    config.enabled = False
    config.refresh_token_enabled = False

    provider = MagicMock()
    auth_manager = SimpleNamespace(provider=provider)
    middleware = RefreshTokenMiddleware(config, auth_manager)

    headers = {"x-openbridge-token": "raw-ob-token:abcdef1234567890"}
    ctx = DummyContext(DummyFastMCPContext(headers))

    captured = {}

    async def capturing_call_next(c):
        captured["token"] = get_refresh_token_override()
        return "ok"

    result = await middleware.on_request(ctx, capturing_call_next)

    assert result == "ok"
    assert captured["token"] == "raw-ob-token:abcdef1234567890"


@pytest.mark.asyncio
async def test_gateway_oauth_jwt_in_authorization_does_not_set_contextvar():
    """Authorization fallback is for OpenBridge refresh tokens only.

    In gateway mode, Authorization carries the gateway's OAuth JWT (dot-separated,
    no colon). The pattern guard must reject it so the ContextVar is NOT set
    and the provider keeps its env-var-initialized token.
    """
    from amazon_ads_mcp.auth.session_state import get_refresh_token_override

    config = AuthConfig()
    config.enabled = False
    config.refresh_token_enabled = False
    # Configure the colon heuristic pattern that OpenBridge uses
    config.refresh_token_pattern = lambda t: ":" in t and len(t) > 20

    provider = MagicMock()
    auth_manager = SimpleNamespace(provider=provider)
    middleware = RefreshTokenMiddleware(config, auth_manager)

    # Gateway OAuth JWT — dot-separated, no colon
    gateway_jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"
    headers = {"authorization": f"Bearer {gateway_jwt}"}
    ctx = DummyContext(DummyFastMCPContext(headers))

    captured = {}

    async def capturing_call_next(c):
        captured["token"] = get_refresh_token_override()
        return "ok"

    result = await middleware.on_request(ctx, capturing_call_next)

    assert result == "ok"
    assert captured["token"] is None


@pytest.mark.asyncio
async def test_validate_jwt_without_signature_success():
    config = AuthConfig()
    config.enabled = True
    config.jwt_validation_enabled = True
    config.jwt_verify_signature = False

    payload = {
        "user_id": "user",
        "account_id": "account",
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).timestamp(),
    }
    token = _make_token(payload)

    middleware = JWTAuthenticationMiddleware(config)
    claims = await middleware._validate_jwt_without_signature(token)

    assert claims["user_id"] == "user"
    assert claims["account_id"] == "account"


@pytest.mark.asyncio
async def test_validate_jwt_without_signature_missing_claims():
    config = AuthConfig()
    config.enabled = True
    config.jwt_validation_enabled = True
    config.jwt_verify_signature = False

    token = _make_token({"user_id": "user"})
    middleware = JWTAuthenticationMiddleware(config)

    claims = await middleware._validate_jwt_without_signature(token)

    assert claims is None


@pytest.mark.asyncio
async def test_validate_jwt_without_signature_expired():
    config = AuthConfig()
    config.enabled = True
    config.jwt_validation_enabled = True
    config.jwt_verify_signature = False

    payload = {
        "user_id": "user",
        "account_id": "account",
        "expires_at": (datetime.now(timezone.utc) - timedelta(minutes=1)).timestamp(),
    }
    token = _make_token(payload)

    middleware = JWTAuthenticationMiddleware(config)
    claims = await middleware._validate_jwt_without_signature(token)

    assert claims is None


# ---------------------------------------------------------------------------
# Token swap detection (multi-tenant session safety)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_token_swap_clears_tenant_state():
    """When refresh token changes mid-session, identity/credentials/profiles are cleared."""
    from amazon_ads_mcp.auth.session_state import (
        get_active_credentials,
        get_active_identity,
        get_active_profiles,
        get_last_seen_token_fingerprint,
        reset_all_session_state,
        set_active_credentials,
        set_active_identity,
        set_active_profiles,
        set_last_seen_token_fingerprint,
        token_fingerprint,
    )
    from amazon_ads_mcp.models import AuthCredentials, Identity

    reset_all_session_state()

    try:
        # --- Seed session with token A's state ---
        token_a = "tenant-a-refresh-token:secret123"
        fp_a = token_fingerprint(token_a)
        set_last_seen_token_fingerprint(fp_a)

        identity_a = Identity(id="identity-a", type="openbridge", attributes={"name": "Tenant A"})
        set_active_identity(identity_a)
        set_active_credentials(
            AuthCredentials(
                identity_id="identity-a",
                access_token="access-a",
                expires_at=datetime(2099, 1, 1, tzinfo=timezone.utc),
                base_url="https://example.com",
                headers={},
            )
        )
        set_active_profiles({"identity-a": "profile-100"})

        # Sanity: state is seeded
        assert get_active_identity() is not None
        assert get_active_credentials() is not None
        assert get_active_profiles() == {"identity-a": "profile-100"}

        # --- Send request with token B ---
        token_b = "tenant-b-refresh-token:different456"
        config = AuthConfig()
        config.enabled = False
        config.refresh_token_enabled = False

        provider = MagicMock()
        auth_manager = SimpleNamespace(provider=provider)
        middleware = RefreshTokenMiddleware(config, auth_manager)

        headers = {"authorization": f"Bearer {token_b}"}
        ctx = DummyContext(DummyFastMCPContext(headers))

        captured = {}

        async def capturing_call_next(c):
            captured["identity"] = get_active_identity()
            captured["credentials"] = get_active_credentials()
            captured["profiles"] = get_active_profiles()
            captured["fingerprint"] = get_last_seen_token_fingerprint()
            return "ok"

        result = await middleware.on_request(ctx, capturing_call_next)

        assert result == "ok"
        # Token changed → tenant state cleared
        assert captured["identity"] is None
        assert captured["credentials"] is None
        assert captured["profiles"] == {}
        # Fingerprint updated to token B
        assert captured["fingerprint"] == token_fingerprint(token_b)
    finally:
        reset_all_session_state()


@pytest.mark.asyncio
async def test_same_token_preserves_tenant_state():
    """When the same refresh token is used again, identity/credentials/profiles are preserved."""
    from amazon_ads_mcp.auth.session_state import (
        get_active_credentials,
        get_active_identity,
        get_active_profiles,
        reset_all_session_state,
        set_active_credentials,
        set_active_identity,
        set_active_profiles,
        set_last_seen_token_fingerprint,
        token_fingerprint,
    )
    from amazon_ads_mcp.models import AuthCredentials, Identity

    reset_all_session_state()

    try:
        # --- Seed session with token A's state ---
        token_a = "tenant-a-refresh-token:secret123"
        fp_a = token_fingerprint(token_a)
        set_last_seen_token_fingerprint(fp_a)

        identity_a = Identity(id="identity-a", type="openbridge", attributes={"name": "Tenant A"})
        creds_a = AuthCredentials(
            identity_id="identity-a",
            access_token="access-a",
            expires_at=datetime(2099, 1, 1, tzinfo=timezone.utc),
            base_url="https://example.com",
            headers={},
        )
        set_active_identity(identity_a)
        set_active_credentials(creds_a)
        set_active_profiles({"identity-a": "profile-100"})

        # --- Send another request with the SAME token ---
        config = AuthConfig()
        config.enabled = False
        config.refresh_token_enabled = False

        provider = MagicMock()
        auth_manager = SimpleNamespace(provider=provider)
        middleware = RefreshTokenMiddleware(config, auth_manager)

        headers = {"authorization": f"Bearer {token_a}"}
        ctx = DummyContext(DummyFastMCPContext(headers))

        captured = {}

        async def capturing_call_next(c):
            captured["identity"] = get_active_identity()
            captured["credentials"] = get_active_credentials()
            captured["profiles"] = get_active_profiles()
            return "ok"

        result = await middleware.on_request(ctx, capturing_call_next)

        assert result == "ok"
        # Same token → state preserved
        assert captured["identity"] is identity_a
        assert captured["credentials"] is creds_a
        assert captured["profiles"] == {"identity-a": "profile-100"}
    finally:
        reset_all_session_state()


@pytest.mark.asyncio
async def test_auth_session_state_persists_across_tool_calls():
    """Auth state persists via FastMCP session state across request contexts."""
    from amazon_ads_mcp.auth.session_state import (
        get_active_identity,
        reset_all_session_state,
        set_active_identity,
    )
    from amazon_ads_mcp.middleware.authentication import AUTH_SESSION_STATE_KEY
    from amazon_ads_mcp.models import Identity

    reset_all_session_state()
    middleware = AuthSessionStateMiddleware()
    fastmcp_context = DummyStateFastMCPContext()

    # Request 1: set identity and persist it into FastMCP context state.
    ctx1 = DummyContext(fastmcp_context)

    async def first_call_next(_):
        set_active_identity(Identity(id="3175", type="openbridge", attributes={"name": "OB"}))
        return "ok-1"

    assert await middleware.on_request(ctx1, first_call_next) == "ok-1"
    assert fastmcp_context._state[AUTH_SESSION_STATE_KEY]["active_identity"]["id"] == "3175"
    assert get_active_identity() is None

    # Simulate next call in a fresh async context with empty ContextVars.
    reset_all_session_state()
    assert get_active_identity() is None

    # Request 2: middleware hydrates from FastMCP state before tool executes.
    ctx2 = DummyContext(fastmcp_context)

    async def second_call_next(_):
        current = get_active_identity()
        return current.id if current else None

    assert await middleware.on_request(ctx2, second_call_next) == "3175"
    assert get_active_identity() is None


@pytest.mark.asyncio
async def test_refresh_token_middleware_fails_closed_on_unexpected_error():
    """Unexpected errors during auth pre-processing must reject the request,
    not silently continue with a missing/stale identity."""
    from fastmcp.exceptions import ToolError

    config = AuthConfig()
    config.enabled = False
    config.refresh_token_enabled = False

    middleware = RefreshTokenMiddleware(config, auth_manager=None)

    class ExplodingRequest:
        @property
        def headers(self):
            raise RuntimeError("boom: headers unavailable")

    class ExplodingFastMCPContext:
        def __init__(self):
            self.request_context = DummyRequestContext(ExplodingRequest())

    ctx = DummyContext(ExplodingFastMCPContext())

    async def call_next(_):
        pytest.fail(
            "call_next must not run after auth pre-processing raises"
        )

    with pytest.raises(ToolError):
        await middleware.on_request(ctx, call_next)
