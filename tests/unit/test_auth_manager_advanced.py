from datetime import datetime, timedelta, timezone

import pytest

from amazon_ads_mcp.auth.base import BaseAmazonAdsProvider, BaseIdentityProvider
from amazon_ads_mcp.auth.manager import AuthManager
from amazon_ads_mcp.auth.token_store import InMemoryTokenStore, TokenKind
from amazon_ads_mcp.models import AuthCredentials, Identity, Token


class MultiIdentityProvider(BaseAmazonAdsProvider, BaseIdentityProvider):
    def __init__(self, identities, headers_identity_specific=False):
        self._identities = {identity.id: identity for identity in identities}
        self._headers_identity_specific = headers_identity_specific
        self.identity_credentials_calls = 0

    @property
    def provider_type(self) -> str:
        return "multi"

    @property
    def region(self) -> str:
        return "na"

    async def initialize(self) -> None:
        return None

    async def get_token(self) -> Token:
        return Token(
            value="provider-token",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )

    async def validate_token(self, token: Token) -> bool:
        return token.expires_at > datetime.now(timezone.utc)

    async def get_headers(self) -> dict:
        return {"Amazon-Advertising-API-ClientId": "client-id"}

    async def close(self) -> None:
        return None

    async def list_identities(self, **kwargs):
        return list(self._identities.values())

    async def get_identity(self, identity_id: str):
        return self._identities.get(identity_id)

    async def get_identity_credentials(self, identity_id: str) -> AuthCredentials:
        self.identity_credentials_calls += 1
        return AuthCredentials(
            identity_id=identity_id,
            access_token=f"token-{identity_id}",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            base_url="https://example.com",
            headers={"Amazon-Advertising-API-ClientId": "client-id"},
        )

    def headers_are_identity_specific(self) -> bool:
        return self._headers_identity_specific


class SingleIdentityProvider(BaseAmazonAdsProvider):
    def __init__(self, token_value="single-token"):
        self._token = Token(
            value=token_value,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )

    @property
    def provider_type(self) -> str:
        return "single"

    @property
    def region(self) -> str:
        return "na"

    async def initialize(self) -> None:
        return None

    async def get_token(self) -> Token:
        return self._token

    async def validate_token(self, token: Token) -> bool:
        return token.expires_at > datetime.now(timezone.utc)

    async def get_headers(self) -> dict:
        return {"Amazon-Advertising-API-ClientId": "client-id"}

    async def close(self) -> None:
        return None


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
async def test_active_profile_tracking_per_identity(auth_manager):
    identities = [
        Identity(id="id-1", type="multi", attributes={"region": "na"}),
    ]
    auth_manager.provider = MultiIdentityProvider(identities)

    await auth_manager.set_active_identity("id-1")
    auth_manager.set_active_profile_id("profile-1")

    assert auth_manager.get_active_profile_id() == "profile-1"
    assert auth_manager.get_profile_source() == "explicit"

    auth_manager.clear_active_profile_id()
    assert auth_manager.get_active_profile_id() is None


@pytest.mark.asyncio
async def test_switch_identity_clears_cached_credentials(auth_manager):
    identities = [
        Identity(id="id-1", type="multi", attributes={}),
        Identity(id="id-2", type="multi", attributes={}),
    ]
    auth_manager.provider = MultiIdentityProvider(identities)

    from amazon_ads_mcp.auth.session_state import get_active_credentials, set_active_credentials

    set_active_credentials(AuthCredentials(
        identity_id="id-1",
        access_token="token",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        base_url="https://example.com",
        headers={},
    ))

    await auth_manager.set_active_identity("id-2")

    assert get_active_credentials() is None


@pytest.mark.asyncio
async def test_get_active_credentials_uses_cached_token(auth_manager):
    identity = Identity(id="id-1", type="multi", attributes={"region": "na"})
    provider = MultiIdentityProvider([identity])
    auth_manager.provider = provider

    await auth_manager.set_active_identity("id-1")
    await auth_manager.set_token(
        provider_type="multi",
        identity_id="id-1",
        token_kind=TokenKind.ACCESS,
        token="cached-token",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        region="na",
    )

    credentials = await auth_manager.get_active_credentials()

    assert credentials.access_token == "cached-token"
    assert provider.identity_credentials_calls == 0


@pytest.mark.asyncio
async def test_get_active_credentials_fetches_when_headers_specific(auth_manager):
    identity = Identity(id="id-1", type="multi", attributes={"region": "na"})
    provider = MultiIdentityProvider([identity], headers_identity_specific=True)
    auth_manager.provider = provider

    await auth_manager.set_active_identity("id-1")
    await auth_manager.set_token(
        provider_type="multi",
        identity_id="id-1",
        token_kind=TokenKind.ACCESS,
        token="cached-token",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        region="na",
    )

    credentials = await auth_manager.get_active_credentials()

    assert credentials.access_token == "token-id-1"
    assert provider.identity_credentials_calls == 1


@pytest.mark.asyncio
async def test_single_identity_credentials_cached(auth_manager):
    auth_manager.provider = SingleIdentityProvider(token_value="single-token")

    creds_first = await auth_manager.get_active_credentials()
    auth_manager.provider._token = Token(
        value="new-token",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    creds_second = await auth_manager.get_active_credentials()

    assert creds_first.access_token == "single-token"
    assert creds_second.access_token == "single-token"


@pytest.mark.asyncio
async def test_close_clears_token_store(auth_manager):
    identity = Identity(id="id-1", type="multi", attributes={"region": "na"})
    auth_manager.provider = MultiIdentityProvider([identity])

    await auth_manager.set_token(
        provider_type="multi",
        identity_id="id-1",
        token_kind=TokenKind.ACCESS,
        token="token",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )

    await auth_manager.close()

    assert auth_manager.token_store._store == {}


def test_reset_creates_new_instance(monkeypatch):
    AuthManager.reset()
    monkeypatch.setattr(AuthManager, "_setup_provider", lambda self: None)
    first = AuthManager()

    AuthManager.reset()
    monkeypatch.setattr(AuthManager, "_setup_provider", lambda self: None)
    second = AuthManager()

    assert first is not second


# ---------------------------------------------------------------------------
# get_active_credentials() hard stop — token fingerprint mismatch
# ---------------------------------------------------------------------------


class TestCredentialsFingerprintGuard:
    """The manager-level hard stop clears stale tenant state."""

    @pytest.fixture(autouse=True)
    def _clean_session_state(self):
        from amazon_ads_mcp.auth.session_state import reset_all_session_state

        reset_all_session_state()
        yield
        reset_all_session_state()

    @pytest.fixture
    def auth_manager(self, monkeypatch):
        AuthManager.reset()
        monkeypatch.setattr(AuthManager, "_setup_provider", lambda self: None)
        mgr = AuthManager()
        identities = [
            Identity(id="id-a", type="openbridge", attributes={"name": "A"}),
            Identity(id="id-b", type="openbridge", attributes={"name": "B"}),
        ]
        mgr.provider = MultiIdentityProvider(identities)
        mgr._token_store = InMemoryTokenStore()
        return mgr

    @pytest.mark.asyncio
    async def test_fingerprint_mismatch_clears_stale_identity(self, auth_manager):
        """Cached identity from token A is rejected when token B is active."""
        from amazon_ads_mcp.auth.session_state import (
            set_active_credentials,
            set_active_identity,
            set_active_profiles,
            set_last_seen_token_fingerprint,
            set_refresh_token_override,
            token_fingerprint,
        )

        # Seed: identity established under token A
        token_a = "tenant-a:secret"
        set_last_seen_token_fingerprint(token_fingerprint(token_a))
        set_active_identity(
            Identity(id="id-a", type="openbridge", attributes={"name": "A"})
        )
        set_active_credentials(
            AuthCredentials(
                identity_id="id-a",
                access_token="stale",
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
                base_url="https://example.com",
                headers={},
            )
        )
        set_active_profiles({"id-a": "profile-100"})

        # Request arrives with token B
        token_b = "tenant-b:different"
        set_refresh_token_override(token_b)

        # Guard should detect mismatch, clear state, and fall through
        # to ensure_default_identity / RuntimeError.
        # Since no default identity is configured, it raises.
        with pytest.raises(RuntimeError, match="No active identity set"):
            await auth_manager.get_active_credentials()

    @pytest.mark.asyncio
    async def test_no_token_with_prior_fingerprint_clears_identity(self, auth_manager):
        """If a prior request had a token but this one doesn't, stale identity is cleared."""
        from amazon_ads_mcp.auth.session_state import (
            set_active_identity,
            set_last_seen_token_fingerprint,
            set_refresh_token_override,
            token_fingerprint,
        )

        # Seed: identity established under a token
        set_last_seen_token_fingerprint(token_fingerprint("tenant-a:secret"))
        set_active_identity(
            Identity(id="id-a", type="openbridge", attributes={"name": "A"})
        )

        # This request has NO token override
        set_refresh_token_override(None)

        with pytest.raises(RuntimeError, match="No active identity set"):
            await auth_manager.get_active_credentials()

    @pytest.mark.asyncio
    async def test_same_fingerprint_preserves_identity(self, auth_manager):
        """Same token fingerprint does not trigger state clearing."""
        from amazon_ads_mcp.auth.session_state import (
            get_active_identity,
            set_active_credentials,
            set_active_identity,
            set_last_seen_token_fingerprint,
            set_refresh_token_override,
            token_fingerprint,
        )

        token_a = "tenant-a:secret"
        fp = token_fingerprint(token_a)
        set_last_seen_token_fingerprint(fp)

        identity = Identity(id="id-a", type="openbridge", attributes={"name": "A"})
        set_active_identity(identity)
        set_active_credentials(
            AuthCredentials(
                identity_id="id-a",
                access_token="valid",
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
                base_url="https://example.com",
                headers={"Amazon-Advertising-API-ClientId": "client-id"},
            )
        )

        # Same token on this request
        set_refresh_token_override(token_a)

        creds = await auth_manager.get_active_credentials()

        # Identity preserved, credentials returned
        assert get_active_identity() is identity
        assert creds.identity_id == "id-a"

    @pytest.mark.asyncio
    async def test_no_request_token_uses_provider_fallback_fingerprint(self, auth_manager):
        """No per-request token preserves identity when provider fallback token matches."""
        from amazon_ads_mcp.auth.session_state import (
            get_active_identity,
            set_active_identity,
            set_last_seen_token_fingerprint,
            set_refresh_token_override,
            token_fingerprint,
        )

        token_a = "tenant-a:secret"
        set_last_seen_token_fingerprint(token_fingerprint(token_a))
        identity = Identity(id="id-a", type="openbridge", attributes={"name": "A"})
        set_active_identity(identity)

        # No per-request token on this call.
        set_refresh_token_override(None)
        # Provider fallback token is stable and matches prior session fingerprint.
        auth_manager.provider._get_effective_refresh_token = lambda: token_a

        creds = await auth_manager.get_active_credentials()

        assert get_active_identity() is identity
        assert creds.identity_id == "id-a"
