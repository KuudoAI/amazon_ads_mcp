from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from amazon_ads_mcp.auth.token_store import TokenKind
from amazon_ads_mcp.middleware.oauth import OAuthTokenMiddleware


class DummyFastMCPContext:
    def __init__(self, tokens_data=None, auth_manager=object()):
        self._tokens_data = tokens_data
        self.set_calls = []
        if auth_manager is not None:
            self.auth_manager = auth_manager

    async def get_state(self, key):
        if key == "oauth_tokens":
            return self._tokens_data
        return None

    async def set_state(self, key, value):
        self.set_calls.append((key, value))


class DummyContext:
    def __init__(self, fastmcp_context, message=None):
        self.fastmcp_context = fastmcp_context
        self.message = message


@pytest.mark.asyncio
async def test_oauth_middleware_skips_oauth_tools():
    middleware = OAuthTokenMiddleware(client_id="cid", client_secret="secret")
    ctx = DummyContext(
        fastmcp_context=DummyFastMCPContext(tokens_data={}),
        message=SimpleNamespace(name="refresh_oauth_token"),
    )
    call_next = AsyncMock(return_value="ok")

    result = await middleware.on_call_tool(ctx, call_next)

    assert result == "ok"
    call_next.assert_awaited_once()
    assert ctx.fastmcp_context.set_calls == []


@pytest.mark.asyncio
async def test_oauth_middleware_sets_context_tokens_without_auth_manager():
    tokens_data = {
        "access_token": "access",
        "refresh_token": "refresh",
        "expires_in": 3600,
        "obtained_at": datetime.now(timezone.utc).isoformat(),
    }
    ctx = DummyContext(fastmcp_context=DummyFastMCPContext(tokens_data, auth_manager=None))
    call_next = AsyncMock(return_value="ok")
    middleware = OAuthTokenMiddleware(client_id="cid", client_secret="secret")

    await middleware.on_call_tool(ctx, call_next)

    keys = {key for key, _ in ctx.fastmcp_context.set_calls}
    assert "current_access_token" in keys
    assert "current_refresh_token" in keys


@pytest.mark.asyncio
async def test_oauth_middleware_refreshes_expired_token():
    tokens_data = {
        "access_token": "old-access",
        "refresh_token": "refresh",
        "expires_in": 1,
        "obtained_at": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
    }
    ctx = DummyContext(fastmcp_context=DummyFastMCPContext(tokens_data, auth_manager=None))
    call_next = AsyncMock(return_value="ok")
    middleware = OAuthTokenMiddleware(client_id="cid", client_secret="secret")
    middleware.refresh_token = AsyncMock(
        return_value={"access_token": "new-access", "expires_in": 1800}
    )

    await middleware.on_call_tool(ctx, call_next)

    updated = [
        value for key, value in ctx.fastmcp_context.set_calls if key == "oauth_tokens"
    ]
    assert updated
    assert updated[0]["access_token"] == "new-access"


@pytest.mark.asyncio
async def test_oauth_middleware_updates_auth_manager():
    tokens_data = {
        "access_token": "access",
        "refresh_token": "refresh",
        "expires_in": 3600,
        "obtained_at": datetime.now(timezone.utc).isoformat(),
    }
    auth_manager = SimpleNamespace(
        set_token=AsyncMock(),
        get_active_identity=MagicMock(return_value=None),
        set_active_identity=AsyncMock(),
    )
    ctx = DummyContext(fastmcp_context=DummyFastMCPContext(tokens_data, auth_manager))
    call_next = AsyncMock(return_value="ok")
    middleware = OAuthTokenMiddleware(client_id="cid", client_secret="secret")

    await middleware.on_call_tool(ctx, call_next)

    token_kinds = {call.kwargs["token_kind"] for call in auth_manager.set_token.call_args_list}
    assert TokenKind.ACCESS in token_kinds
    assert TokenKind.REFRESH in token_kinds
    auth_manager.set_active_identity.assert_awaited_once_with("oauth")
