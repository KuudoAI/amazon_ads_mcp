"""Authentication tests aligned to current auth manager and client behavior."""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from amazon_ads_mcp.auth.manager import AuthManager
from amazon_ads_mcp.auth.base import BaseIdentityProvider, BaseAmazonAdsProvider
from amazon_ads_mcp.models import AuthCredentials, Identity, Token
from amazon_ads_mcp.utils.http_client import AuthenticatedClient


@dataclass
class FakeIdentity:
    id: str
    attributes: dict


class FakeProvider(BaseAmazonAdsProvider, BaseIdentityProvider):
    """Fake provider that implements the correct interfaces."""
    
    @property
    def provider_type(self) -> str:
        """Return the provider type identifier."""
        return "fake"
    
    @property
    def region(self) -> str:
        """Get the current region."""
        return "na"
    
    def __init__(self):
        self._identity = Identity(id="id-1", type="fake", attributes={"name": "Test"})
        self._token = Token(
            value="fake_token",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            token_type="Bearer"
        )

    async def initialize(self):
        """Initialize the provider."""
        pass

    async def get_token(self) -> Token:
        """Get authentication token."""
        return self._token

    async def validate_token(self, token: Token) -> bool:
        """Validate token."""
        return datetime.now(timezone.utc) < token.expires_at

    async def get_headers(self) -> dict:
        """Get headers for API requests."""
        return {
            "Authorization": "Bearer tok",
            "Amazon-Advertising-API-ClientId": "cid",
        }

    async def close(self):
        """Clean up resources."""
        pass

    async def list_identities(self, **kwargs):  # pragma: no cover - not used here
        return [self._identity]

    async def get_identity(self, identity_id: str):
        return self._identity if identity_id == self._identity.id else None

    async def get_identity_credentials(self, identity_id: str) -> AuthCredentials:
        return AuthCredentials(
            identity_id=identity_id,
            access_token="tok",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            base_url="https://example.com",
            headers={
                "Authorization": "Bearer tok",
                "Amazon-Advertising-API-ClientId": "cid",
            },
        )


@pytest.mark.asyncio
async def test_auth_manager_headers_and_scope(monkeypatch):
    monkeypatch.setenv("AUTH_METHOD", "direct")
    monkeypatch.setenv("AMAZON_AD_API_CLIENT_ID", "fake")
    monkeypatch.setenv("AMAZON_AD_API_CLIENT_SECRET", "fake")
    from amazon_ads_mcp.config.settings import Settings
    monkeypatch.setattr("amazon_ads_mcp.auth.manager.settings", Settings())
    AuthManager.reset()
    am = AuthManager()
    am.provider = FakeProvider()
    # Set active identity and a profile scope
    await am.set_active_identity("id-1")
    am.set_active_profile_id("prof-123")
    headers = await am.get_headers()
    assert headers["Authorization"].startswith("Bearer ")
    assert headers["Amazon-Advertising-API-ClientId"] == "cid"
    assert headers["Amazon-Advertising-API-Scope"] == "prof-123"


@pytest.mark.asyncio
async def test_authenticated_client_injects_headers(monkeypatch):
    monkeypatch.setenv("AUTH_METHOD", "direct")
    monkeypatch.setenv("AMAZON_AD_API_CLIENT_ID", "fake")
    monkeypatch.setenv("AMAZON_AD_API_CLIENT_SECRET", "fake")
    from amazon_ads_mcp.config.settings import Settings
    monkeypatch.setattr("amazon_ads_mcp.auth.manager.settings", Settings())
    AuthManager.reset()
    am = AuthManager()
    am.provider = FakeProvider()
    await am.set_active_identity("id-1")
    # No scope on profiles root

    captured = {}

    async def fake_send(self, request: httpx.Request, **kwargs):
        captured["headers"] = request.headers
        return httpx.Response(200, request=request)

    # Patch base send to intercept
    monkeypatch.setattr(httpx.AsyncClient, "send", fake_send, raising=True)

    async with AuthenticatedClient(base_url="https://example.com", auth_manager=am) as c:
        await c.get("/v2/profiles")

    hdrs: httpx.Headers = captured["headers"]
    assert hdrs.get("Authorization", "").startswith("Bearer ")
    assert hdrs.get("Amazon-Advertising-API-ClientId") == "cid"
