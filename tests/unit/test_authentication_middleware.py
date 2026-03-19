from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import jwt
import pytest

from amazon_ads_mcp.middleware.authentication import (
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
