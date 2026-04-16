"""Verify that concurrent ``get_active_credentials`` for the same
identity coalesce into a single provider fetch."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from amazon_ads_mcp.auth.base import BaseAmazonAdsProvider, BaseIdentityProvider
from amazon_ads_mcp.auth.manager import AuthManager
from amazon_ads_mcp.auth.token_store import InMemoryTokenStore
from amazon_ads_mcp.models import AuthCredentials, Identity, Token


class SlowIdentityProvider(BaseAmazonAdsProvider, BaseIdentityProvider):
    """Provider whose ``get_identity_credentials`` sleeps, so N concurrent
    callers racing past the cache check overlap in time."""

    def __init__(self, identity_id: str, delay: float = 0.05) -> None:
        self._identity = Identity(
            id=identity_id, type="multi", attributes={"region": "na"}
        )
        self._delay = delay
        self.calls = 0

    @property
    def provider_type(self) -> str:
        return "multi"

    @property
    def region(self) -> str:
        return "na"

    async def initialize(self) -> None: ...

    async def get_token(self) -> Token:
        return Token(
            value="static",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )

    async def validate_token(self, token: Token) -> bool:
        return True

    async def get_headers(self) -> dict:
        return {"Amazon-Advertising-API-ClientId": "client-id"}

    async def close(self) -> None: ...

    async def list_identities(self, **kwargs):
        return [self._identity]

    async def get_identity(self, identity_id: str):
        return self._identity if identity_id == self._identity.id else None

    async def get_identity_credentials(self, identity_id: str) -> AuthCredentials:
        self.calls += 1
        await asyncio.sleep(self._delay)
        return AuthCredentials(
            identity_id=identity_id,
            access_token=f"fresh-{self.calls}",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            base_url="https://example.com",
            headers={"Amazon-Advertising-API-ClientId": "client-id"},
        )


@pytest.fixture
def auth_manager(monkeypatch):
    AuthManager.reset()
    monkeypatch.setattr(AuthManager, "_setup_provider", lambda self: None)
    manager = AuthManager()
    manager.provider = None
    manager._token_store = InMemoryTokenStore()
    manager._default_profile_id = None
    yield manager
    AuthManager.reset()


@pytest.mark.asyncio
async def test_concurrent_refreshes_coalesce(auth_manager):
    provider = SlowIdentityProvider("id-1", delay=0.05)
    auth_manager.provider = provider
    await auth_manager.set_active_identity("id-1")

    results = await asyncio.gather(
        *[auth_manager.get_active_credentials() for _ in range(50)]
    )

    # Only one provider fetch should have happened.
    assert provider.calls == 1
    # All callers received the same credential object reference.
    assert all(r.access_token == "fresh-1" for r in results)
    assert all(r.identity_id == "id-1" for r in results)
