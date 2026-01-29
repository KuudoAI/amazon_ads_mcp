from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

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
async def test_refresh_token_middleware_sets_provider_refresh_token():
    config = AuthConfig()
    config.enabled = False
    config.refresh_token_enabled = False

    provider = MagicMock()
    auth_manager = SimpleNamespace(provider=provider)
    middleware = RefreshTokenMiddleware(config, auth_manager)

    headers = {"authorization": "Bearer refresh-token"}
    ctx = DummyContext(DummyFastMCPContext(headers))
    call_next = AsyncMock(return_value="ok")

    result = await middleware.on_request(ctx, call_next)

    assert result == "ok"
    provider.set_refresh_token.assert_called_once_with("refresh-token")


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
