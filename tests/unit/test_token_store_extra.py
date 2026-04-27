"""Coverage-pushing tests for ``auth.token_store`` core types and the
``InMemoryTokenStore`` implementation.

Existing ``tests/unit/test_token_store.py`` covers the high-level flows;
this file rounds out the surface — TokenKey serialization edge cases,
TokenEntry expiry math, pattern-invalidation matrices, and LRU eviction.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from amazon_ads_mcp.auth.token_store import (
    InMemoryTokenStore,
    TokenEntry,
    TokenKey,
    TokenKind,
)


# --- TokenKey -------------------------------------------------------------


class TestTokenKey:
    def test_to_string_minimal(self) -> None:
        key = TokenKey(
            provider_type="direct",
            identity_id="default",
            token_kind=TokenKind.ACCESS,
        )
        # Defaults: region/marketplace/profile → global/none/none
        assert key.to_string() == "direct:default:access:global:none:none"

    def test_to_string_full(self) -> None:
        key = TokenKey(
            provider_type="openbridge",
            identity_id="user-123",
            token_kind=TokenKind.PROVIDER_JWT,
            region="eu",
            marketplace="ATVPDKIKX0DER",
            profile_id="profile-456",
        )
        assert key.to_string() == (
            "openbridge:user-123:provider_jwt:eu:ATVPDKIKX0DER:profile-456"
        )

    def test_round_trip(self) -> None:
        original = TokenKey(
            provider_type="direct",
            identity_id="x",
            token_kind=TokenKind.REFRESH,
            region="na",
            profile_id="p1",
        )
        round_tripped = TokenKey.from_string(original.to_string())
        assert round_tripped == original

    def test_round_trip_with_none_fields(self) -> None:
        """Optional fields encoded as 'global'/'none' must decode back to None."""
        original = TokenKey(
            provider_type="direct",
            identity_id="x",
            token_kind=TokenKind.ACCESS,
        )
        round_tripped = TokenKey.from_string(original.to_string())
        assert round_tripped.region is None
        assert round_tripped.marketplace is None
        assert round_tripped.profile_id is None

    def test_from_string_rejects_malformed(self) -> None:
        with pytest.raises(ValueError, match="Invalid token key"):
            TokenKey.from_string("only:three:parts")


# --- TokenEntry -----------------------------------------------------------


class TestTokenEntry:
    def test_created_at_defaults_to_now(self) -> None:
        entry = TokenEntry(
            value="x",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            metadata={},
        )
        # Within a few seconds of now
        delta = abs((datetime.now(timezone.utc) - entry.created_at).total_seconds())
        assert delta < 5

    def test_is_expired_when_past_expiry(self) -> None:
        entry = TokenEntry(
            value="x",
            expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
            metadata={},
        )
        assert entry.is_expired() is True

    def test_is_expired_within_buffer_window(self) -> None:
        """5-min default buffer means expiry-soon counts as expired."""
        entry = TokenEntry(
            value="x",
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=60),
            metadata={},
        )
        # Default buffer is 300s; 60s < 300s → considered expired
        assert entry.is_expired() is True

    def test_is_expired_with_custom_buffer(self) -> None:
        entry = TokenEntry(
            value="x",
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=60),
            metadata={},
        )
        # Custom 10s buffer → 60s ahead is fine
        assert entry.is_expired(buffer_seconds=10) is False

    def test_is_expired_handles_naive_datetime(self) -> None:
        """If a stored expires_at is somehow naive, the function still
        works (it normalizes to UTC internally)."""
        naive = datetime.utcnow() + timedelta(hours=1)
        entry = TokenEntry(value="x", expires_at=naive, metadata={})
        assert entry.is_expired() is False

    def test_to_dict_round_trip(self) -> None:
        original = TokenEntry(
            value="abc",
            expires_at=datetime(2030, 1, 1, tzinfo=timezone.utc),
            metadata={"scope": "test"},
        )
        round_tripped = TokenEntry.from_dict(original.to_dict())
        assert round_tripped.value == original.value
        assert round_tripped.expires_at == original.expires_at
        assert round_tripped.metadata == original.metadata

    def test_from_dict_with_missing_metadata_defaults_to_empty(self) -> None:
        d = {
            "value": "x",
            "expires_at": datetime.now(timezone.utc).isoformat(),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        entry = TokenEntry.from_dict(d)
        assert entry.metadata == {}


# --- InMemoryTokenStore ---------------------------------------------------


@pytest.fixture
def store() -> InMemoryTokenStore:
    return InMemoryTokenStore(max_entries=10, cleanup_interval=999999, default_ttl=3600)


def _key(provider: str = "direct", identity: str = "default", kind=TokenKind.ACCESS,
         region: str | None = None) -> TokenKey:
    return TokenKey(
        provider_type=provider,
        identity_id=identity,
        token_kind=kind,
        region=region,
    )


def _entry(value: str = "tok", hours_until_expiry: int = 1) -> TokenEntry:
    return TokenEntry(
        value=value,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=hours_until_expiry),
        metadata={},
    )


class TestInMemoryTokenStore:
    @pytest.mark.asyncio
    async def test_set_and_get_round_trip(self, store: InMemoryTokenStore) -> None:
        await store.set(_key(), _entry("hello"))
        result = await store.get(_key())
        assert result is not None
        assert result.value == "hello"

    @pytest.mark.asyncio
    async def test_get_missing_returns_none(self, store: InMemoryTokenStore) -> None:
        assert await store.get(_key()) is None

    @pytest.mark.asyncio
    async def test_get_expired_returns_none_and_purges(
        self, store: InMemoryTokenStore
    ) -> None:
        # Use buffer_seconds=0 to bypass the 5-min buffer in is_expired
        expired = TokenEntry(
            value="old",
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
            metadata={},
        )
        await store.set(_key(), expired)
        assert await store.get(_key()) is None
        # Purged from storage too
        assert await store.get(_key()) is None

    @pytest.mark.asyncio
    async def test_invalidate_removes_specific_key(
        self, store: InMemoryTokenStore
    ) -> None:
        await store.set(_key(identity="a"), _entry("a"))
        await store.set(_key(identity="b"), _entry("b"))
        await store.invalidate(_key(identity="a"))
        assert await store.get(_key(identity="a")) is None
        assert await store.get(_key(identity="b")) is not None

    @pytest.mark.asyncio
    async def test_invalidate_missing_key_is_silent(
        self, store: InMemoryTokenStore
    ) -> None:
        # Must not raise on missing key
        await store.invalidate(_key())

    @pytest.mark.asyncio
    async def test_invalidate_pattern_by_provider(
        self, store: InMemoryTokenStore
    ) -> None:
        await store.set(_key(provider="direct"), _entry())
        await store.set(_key(provider="openbridge"), _entry())
        count = await store.invalidate_pattern(provider_type="direct")
        assert count == 1
        assert await store.get(_key(provider="direct")) is None
        assert await store.get(_key(provider="openbridge")) is not None

    @pytest.mark.asyncio
    async def test_invalidate_pattern_by_kind(
        self, store: InMemoryTokenStore
    ) -> None:
        await store.set(_key(kind=TokenKind.ACCESS), _entry())
        await store.set(_key(kind=TokenKind.REFRESH), _entry())
        count = await store.invalidate_pattern(token_kind=TokenKind.ACCESS)
        assert count == 1

    @pytest.mark.asyncio
    async def test_invalidate_pattern_by_region(
        self, store: InMemoryTokenStore
    ) -> None:
        await store.set(_key(region="na"), _entry())
        await store.set(_key(region="eu"), _entry())
        count = await store.invalidate_pattern(region="na")
        assert count == 1

    @pytest.mark.asyncio
    async def test_invalidate_pattern_combined(
        self, store: InMemoryTokenStore
    ) -> None:
        """Combined filters AND together: only entries matching ALL predicates
        are invalidated."""
        await store.set(_key(provider="direct", region="na"), _entry())
        await store.set(_key(provider="direct", region="eu"), _entry())
        await store.set(_key(provider="openbridge", region="na"), _entry())
        count = await store.invalidate_pattern(provider_type="direct", region="na")
        assert count == 1
        assert await store.get(_key(provider="direct", region="eu")) is not None
        assert await store.get(_key(provider="openbridge", region="na")) is not None

    @pytest.mark.asyncio
    async def test_invalidate_pattern_no_match_returns_zero(
        self, store: InMemoryTokenStore
    ) -> None:
        await store.set(_key(), _entry())
        count = await store.invalidate_pattern(provider_type="nonexistent")
        assert count == 0

    @pytest.mark.asyncio
    async def test_clear_removes_all_entries(
        self, store: InMemoryTokenStore
    ) -> None:
        for i in range(5):
            await store.set(_key(identity=f"id-{i}"), _entry())
        await store.clear()
        for i in range(5):
            assert await store.get(_key(identity=f"id-{i}")) is None

    @pytest.mark.asyncio
    async def test_lru_eviction_removes_oldest_when_full(self) -> None:
        """When max_entries is reached, the OLDEST entry (by created_at)
        is evicted on the next set."""
        small = InMemoryTokenStore(max_entries=2, cleanup_interval=999999)
        # First entry
        await small.set(_key(identity="oldest"), _entry("0"))
        # Second entry — under cap
        await small.set(_key(identity="middle"), _entry("1"))
        # Third entry — triggers eviction of oldest
        await small.set(_key(identity="newest"), _entry("2"))

        assert await small.get(_key(identity="oldest")) is None
        assert await small.get(_key(identity="middle")) is not None
        assert await small.get(_key(identity="newest")) is not None


# --- Convenience methods (TokenStore base class) -------------------------


class TestConvenienceAccessTokenMethods:
    @pytest.mark.asyncio
    async def test_set_and_get_access_token_round_trip(
        self, store: InMemoryTokenStore
    ) -> None:
        await store.set_access_token(
            provider_type="direct",
            identity_id="user-1",
            token="mytoken",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            metadata={"scope": "ads"},
            region="na",
        )
        entry = await store.get_access_token(
            provider_type="direct",
            identity_id="user-1",
            region="na",
        )
        assert entry is not None
        assert entry.value == "mytoken"
        assert entry.metadata == {"scope": "ads"}

    @pytest.mark.asyncio
    async def test_get_access_token_missing_returns_none(
        self, store: InMemoryTokenStore
    ) -> None:
        result = await store.get_access_token(
            provider_type="direct", identity_id="ghost"
        )
        assert result is None
