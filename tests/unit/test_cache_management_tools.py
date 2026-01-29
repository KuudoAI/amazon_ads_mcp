from types import SimpleNamespace

import pytest

from amazon_ads_mcp.tools import cache_management


@pytest.mark.asyncio
async def test_clear_identity_cache(monkeypatch):
    provider = SimpleNamespace(_identities_cache={"key": [1, 2]})
    manager = SimpleNamespace(provider=provider)
    monkeypatch.setattr(cache_management, "get_auth_manager", lambda: manager)

    result = await cache_management.clear_identity_cache()

    assert result["success"] is True
    assert result["cache_size_before"] == 1
    assert result["cache_size_after"] == 0
    assert provider._identities_cache == {}


@pytest.mark.asyncio
async def test_clear_identity_cache_no_cache(monkeypatch):
    provider = SimpleNamespace()
    manager = SimpleNamespace(provider=provider)
    monkeypatch.setattr(cache_management, "get_auth_manager", lambda: manager)

    result = await cache_management.clear_identity_cache()

    assert result["success"] is True
    assert result["cache_size_before"] == 0
    assert result["cache_size_after"] == 0


@pytest.mark.asyncio
async def test_get_cache_status(monkeypatch):
    provider = SimpleNamespace(
        _identities_cache={
            "a": [1, 2, 3],
            "b": [4],
        }
    )
    manager = SimpleNamespace(provider=provider)
    monkeypatch.setattr(cache_management, "get_auth_manager", lambda: manager)

    result = await cache_management.get_cache_status()

    assert result["success"] is True
    assert result["cache_enabled"] is True
    assert result["cache_size"] == 2
    assert result["total_identities_cached"] == 4
    assert len(result["cache_entries"]) == 2


@pytest.mark.asyncio
async def test_get_cache_status_no_cache(monkeypatch):
    provider = SimpleNamespace()
    manager = SimpleNamespace(provider=provider)
    monkeypatch.setattr(cache_management, "get_auth_manager", lambda: manager)

    result = await cache_management.get_cache_status()

    assert result["success"] is True
    assert result["cache_enabled"] is False
