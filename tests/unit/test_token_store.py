from datetime import datetime, timedelta, timezone

import pytest
from cryptography.fernet import Fernet

from amazon_ads_mcp.auth import token_store as token_store_module
from amazon_ads_mcp.auth.token_store import (
    InMemoryTokenStore,
    PersistentTokenStore,
    TokenEntry,
    TokenKey,
    TokenKind,
    create_token_store,
)


@pytest.mark.asyncio
async def test_inmemory_token_store_set_get_invalidate():
    store = InMemoryTokenStore()
    key = TokenKey("direct", "id", TokenKind.ACCESS, region="na")
    entry = TokenEntry(
        value="token",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        metadata={},
    )

    await store.set(key, entry)
    assert await store.get(key) is not None

    await store.invalidate(key)
    assert await store.get(key) is None


@pytest.mark.asyncio
async def test_inmemory_token_store_expired_cleanup():
    store = InMemoryTokenStore()
    key = TokenKey("direct", "id", TokenKind.ACCESS)
    entry = TokenEntry(
        value="token",
        expires_at=datetime.now(timezone.utc) - timedelta(minutes=10),
        metadata={},
    )

    await store.set(key, entry)
    assert await store.get(key) is None


@pytest.mark.asyncio
async def test_inmemory_token_store_invalidate_pattern():
    store = InMemoryTokenStore()
    key_one = TokenKey("direct", "id", TokenKind.ACCESS)
    key_two = TokenKey("openbridge", "id", TokenKind.ACCESS)
    entry = TokenEntry(
        value="token",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        metadata={},
    )

    await store.set(key_one, entry)
    await store.set(key_two, entry)

    removed = await store.invalidate_pattern(provider_type="direct")

    assert removed == 1
    assert await store.get(key_one) is None
    assert await store.get(key_two) is not None


@pytest.mark.asyncio
async def test_persistent_store_persists_refresh_only(tmp_path):
    storage_path = tmp_path / "tokens.json"
    store = PersistentTokenStore(storage_path=storage_path, encrypt_at_rest=False)

    refresh_key = TokenKey("direct", "id", TokenKind.REFRESH)
    access_key = TokenKey("direct", "id", TokenKind.ACCESS)

    entry = TokenEntry(
        value="token",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        metadata={},
    )

    await store.set(refresh_key, entry)
    await store.set(access_key, entry)

    data = storage_path.read_text()
    assert refresh_key.to_string() in data
    assert access_key.to_string() not in data


@pytest.mark.asyncio
async def test_persistent_store_encrypts_data(tmp_path, monkeypatch):
    key = Fernet.generate_key().decode("ascii")
    monkeypatch.setenv("AMAZON_ADS_ENCRYPTION_KEY", key)

    storage_path = tmp_path / "tokens.json"
    store = PersistentTokenStore(storage_path=storage_path, encrypt_at_rest=True)

    refresh_key = TokenKey("direct", "id", TokenKind.REFRESH)
    entry = TokenEntry(
        value="token",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        metadata={},
    )

    await store.set(refresh_key, entry)

    data = storage_path.read_text()
    assert "_encrypted" in data


def test_create_token_store_respects_env(tmp_path, monkeypatch):
    monkeypatch.setenv("AMAZON_ADS_TOKEN_PERSIST", "false")
    store = create_token_store(persist=True)
    assert isinstance(store, InMemoryTokenStore)

    monkeypatch.setenv("AMAZON_ADS_TOKEN_PERSIST", "true")
    storage_path = tmp_path / "tokens.json"
    store = create_token_store(persist=False, storage_path=storage_path, encrypt_at_rest=False)
    assert isinstance(store, PersistentTokenStore)


def test_initialize_encryption_requires_crypto(monkeypatch, tmp_path):
    monkeypatch.setattr(token_store_module, "CRYPTOGRAPHY_AVAILABLE", False)
    monkeypatch.delenv("AMAZON_ADS_ALLOW_PLAINTEXT_PERSIST", raising=False)

    storage_path = tmp_path / "tokens.json"

    with pytest.raises(RuntimeError):
        PersistentTokenStore(storage_path=storage_path, encrypt_at_rest=True)
