import types
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from amazon_ads_mcp.tools import oauth as oauth_module
from amazon_ads_mcp.tools.oauth import OAuthTools


class DummySettings:
    ad_api_client_id = "client-id"
    ad_api_client_secret = "client-secret"
    amazon_ads_region = "na"
    mcp_server_port = 9080


class DummyContext:
    def __init__(self):
        self.state = {}

    def set_state(self, key, value):
        self.state[key] = value

    def get_state(self, key):
        return self.state.get(key)


class FakeStateStore:
    def __init__(self, state="state-token"):
        self.state = state
        self.generated = None
        self.validation = (True, None)

    def generate_state(self, auth_url, user_agent=None, ip_address=None, ttl_minutes=10):
        self.generated = {
            "auth_url": auth_url,
            "user_agent": user_agent,
            "ip_address": ip_address,
            "ttl_minutes": ttl_minutes,
        }
        return self.state

    def validate_state(self, state, user_agent=None, ip_address=None):
        return self.validation


class FakeResponse:
    def __init__(self, status_code=200, payload=None, text="OK"):
        self.status_code = status_code
        self._payload = payload or {}
        self.text = text

    def json(self):
        return self._payload


class FakeAsyncClient:
    def __init__(self, response):
        self.response = response
        self.requests = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def post(self, url, data=None):
        self.requests.append({"url": url, "data": data})
        return self.response


@pytest.mark.asyncio
async def test_start_oauth_flow_stores_state(monkeypatch):
    state_store = FakeStateStore()
    monkeypatch.setattr(oauth_module, "get_oauth_state_store", lambda: state_store)

    ctx = DummyContext()
    oauth = OAuthTools(DummySettings())

    result = await oauth.start_oauth_flow(ctx, user_agent="ua", ip_address="1.2.3.4")

    assert result["status"] == "success"
    assert "state-token" in result["auth_url"]
    assert ctx.state["oauth_state"]["state"] == "[REDACTED]"
    assert ctx.state["oauth_state"]["auth_url"] == result["auth_url"]
    assert state_store.generated["user_agent"] == "ua"
    assert state_store.generated["ip_address"] == "1.2.3.4"


@pytest.mark.asyncio
async def test_check_oauth_status_active_tokens(monkeypatch):
    ctx = DummyContext()
    ctx.set_state(
        "oauth_tokens",
        {
            "access_token": "access",
            "refresh_token": "refresh",
            "expires_in": 3600,
            "obtained_at": datetime.now(timezone.utc).isoformat(),
        },
    )

    oauth = OAuthTools(DummySettings())
    result = await oauth.check_oauth_status(ctx)

    assert result["authenticated"] is True
    assert result["status"] == "active"
    assert result["has_refresh_token"] is True
    assert result["access_token_expired"] is False


@pytest.mark.asyncio
async def test_check_oauth_status_pending(monkeypatch):
    ctx = DummyContext()
    ctx.set_state(
        "oauth_state",
        {
            "auth_url": "http://example.com/auth",
            "completed": False,
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
            "state": "[REDACTED]",
        },
    )

    oauth = OAuthTools(DummySettings())
    result = await oauth.check_oauth_status(ctx)

    assert result["authenticated"] is False
    assert result["status"] == "pending"
    assert result["auth_url"] == "http://example.com/auth"


@pytest.mark.asyncio
async def test_check_oauth_status_expired(monkeypatch):
    ctx = DummyContext()
    ctx.set_state(
        "oauth_state",
        {
            "auth_url": "http://example.com/auth",
            "completed": False,
            "expires_at": (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
            "state": "[REDACTED]",
        },
    )

    oauth = OAuthTools(DummySettings())
    result = await oauth.check_oauth_status(ctx)

    assert result["authenticated"] is False
    assert result["status"] == "expired"


@pytest.mark.asyncio
async def test_check_oauth_status_callback_tokens(monkeypatch):
    ctx = DummyContext()
    oauth = OAuthTools(DummySettings())
    oauth._callback_tokens = {
        "access_token": "access",
        "refresh_token": "refresh",
        "expires_in": 3600,
        "scope": "scope",
    }

    result = await oauth.check_oauth_status(ctx)

    assert result["authenticated"] is True
    assert result["status"] == "callback_received"
    assert ctx.state["oauth_tokens"]["access_token"] == "access"


@pytest.mark.asyncio
async def test_refresh_access_token_success(monkeypatch):
    ctx = DummyContext()
    ctx.set_state(
        "oauth_tokens",
        {
            "access_token": "old-access",
            "refresh_token": "refresh",
            "expires_in": 3600,
            "obtained_at": datetime.now(timezone.utc).isoformat(),
        },
    )

    response = FakeResponse(
        200,
        {
            "access_token": "new-access",
            "refresh_token": "new-refresh",
            "expires_in": 1800,
        },
    )

    monkeypatch.setattr(oauth_module.httpx, "AsyncClient", lambda timeout=None: FakeAsyncClient(response))
    monkeypatch.setattr(oauth_module.RegionConfig, "get_oauth_endpoint", lambda region: "https://token")

    secure_store = MagicMock()
    from amazon_ads_mcp.auth import secure_token_store, manager

    monkeypatch.setattr(secure_token_store, "get_secure_token_store", lambda: secure_store)
    monkeypatch.setattr(manager, "get_auth_manager", lambda: None)

    oauth = OAuthTools(DummySettings())
    result = await oauth.refresh_access_token(ctx)

    assert result["status"] == "success"
    assert ctx.state["oauth_tokens"]["access_token"] == "new-access"
    assert secure_store.store_token.called is True


@pytest.mark.asyncio
async def test_refresh_access_token_missing_refresh(monkeypatch):
    ctx = DummyContext()
    oauth = OAuthTools(DummySettings())

    result = await oauth.refresh_access_token(ctx)

    assert result["status"] == "error"
    assert "No refresh token" in result["message"]


@pytest.mark.asyncio
async def test_handle_oauth_callback_success(monkeypatch):
    state_store = FakeStateStore()
    monkeypatch.setattr(oauth_module, "get_oauth_state_store", lambda: state_store)

    response = FakeResponse(
        200,
        {
            "access_token": "access",
            "refresh_token": "refresh",
            "expires_in": 3600,
            "scope": "scope",
        },
    )
    monkeypatch.setattr(oauth_module.httpx, "AsyncClient", lambda timeout=None: FakeAsyncClient(response))
    monkeypatch.setattr(oauth_module.RegionConfig, "get_oauth_endpoint", lambda region: "https://token")

    secure_store = MagicMock()
    from amazon_ads_mcp.auth import secure_token_store, manager

    monkeypatch.setattr(secure_token_store, "get_secure_token_store", lambda: secure_store)

    auth_manager = types.SimpleNamespace(set_token=AsyncMock(), provider=None)
    monkeypatch.setattr(manager, "get_auth_manager", lambda: auth_manager)

    ctx = DummyContext()
    ctx.set_state(
        "oauth_state",
        {
            "auth_url": "http://example.com/auth",
            "completed": False,
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat(),
            "state": "[REDACTED]",
        },
    )

    oauth = OAuthTools(DummySettings())
    result = await oauth.handle_oauth_callback("code", "state", ctx)

    assert result["status"] == "success"
    assert ctx.state["oauth_tokens"]["access_token"] == "access"
    assert ctx.state["oauth_state"]["completed"] is True


@pytest.mark.asyncio
async def test_handle_oauth_callback_invalid_state(monkeypatch):
    state_store = FakeStateStore()
    state_store.validation = (False, "Invalid state")
    monkeypatch.setattr(oauth_module, "get_oauth_state_store", lambda: state_store)

    ctx = DummyContext()
    oauth = OAuthTools(DummySettings())

    result = await oauth.handle_oauth_callback("code", "state", ctx)

    assert result["status"] == "error"
    assert result["message"] == "Invalid state"
