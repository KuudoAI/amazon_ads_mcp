from unittest.mock import AsyncMock

import pytest

from amazon_ads_mcp.tools import profile_listing as listing_tools


SAMPLE_PROFILES = [
    {
        "profileId": 1,
        "countryCode": "US",
        "accountInfo": {"name": "Acme US Seller", "type": "seller"},
    },
    {
        "profileId": 2,
        "countryCode": "US",
        "accountInfo": {"name": "Beta US Vendor", "type": "vendor"},
    },
    {
        "profileId": 3,
        "countryCode": "DE",
        "accountInfo": {"name": "Acme DE Seller", "type": "seller"},
    },
]


@pytest.mark.asyncio
async def test_summarize_profiles_counts(monkeypatch):
    monkeypatch.setattr(
        listing_tools,
        "_get_profiles_cached",
        AsyncMock(return_value=(SAMPLE_PROFILES, False)),
    )

    result = await listing_tools.summarize_profiles()

    assert result["total_count"] == 3
    assert result["by_country"]["US"] == 2
    assert result["by_country"]["DE"] == 1
    assert result["by_type"]["seller"] == 2
    assert result["by_type"]["vendor"] == 1
    assert result["stale"] is False


@pytest.mark.asyncio
async def test_search_profiles_filters(monkeypatch):
    monkeypatch.setattr(
        listing_tools,
        "_get_profiles_cached",
        AsyncMock(return_value=(SAMPLE_PROFILES, False)),
    )

    result = await listing_tools.search_profiles(
        query="Acme", country_code="US", limit=5
    )

    assert result["total_count"] == 1
    assert result["returned_count"] == 1
    assert result["has_more"] is False
    assert result["items"][0]["profile_id"] == "1"


@pytest.mark.asyncio
async def test_page_profiles_offset(monkeypatch):
    monkeypatch.setattr(
        listing_tools,
        "_get_profiles_cached",
        AsyncMock(return_value=(SAMPLE_PROFILES, False)),
    )

    result = await listing_tools.page_profiles(offset=1, limit=1)

    assert result["total_count"] == 3
    assert result["returned_count"] == 1
    assert result["has_more"] is True
    assert result["next_offset"] == 2
    assert result["items"][0]["profile_id"] == "2"


@pytest.mark.asyncio
async def test_profile_cache_returns_cached_when_fresh(monkeypatch):
    cache = listing_tools.ProfileCache(ttl_seconds=300)
    fetcher = AsyncMock(return_value=[{"profileId": 9}])
    key = ("identity-1", "na")

    monkeypatch.setattr(listing_tools.time, "time", lambda: 1000)
    cache._cache[key] = listing_tools.CacheEntry(
        profiles=[{"profileId": 1}],
        timestamp=900,
    )

    profiles, stale = await cache.get_profiles(key, fetcher)

    assert profiles[0]["profileId"] == 1
    assert stale is False
    fetcher.assert_not_awaited()


@pytest.mark.asyncio
async def test_profile_cache_returns_stale_on_fetch_failure(monkeypatch):
    cache = listing_tools.ProfileCache(ttl_seconds=300)
    fetcher = AsyncMock(side_effect=RuntimeError("boom"))
    key = ("identity-1", "na")

    monkeypatch.setattr(listing_tools.time, "time", lambda: 1000)
    cache._cache[key] = listing_tools.CacheEntry(
        profiles=[{"profileId": 2}],
        timestamp=500,
    )

    profiles, stale = await cache.get_profiles(key, fetcher)

    assert profiles[0]["profileId"] == 2
    assert stale is True


@pytest.mark.asyncio
async def test_refresh_profiles_cache_success(monkeypatch):
    monkeypatch.setattr(
        listing_tools,
        "_get_cache_key",
        lambda: ("identity-1", "na"),
    )
    monkeypatch.setattr(
        listing_tools,
        "_get_profiles_cached",
        AsyncMock(return_value=(SAMPLE_PROFILES, False)),
    )
    monkeypatch.setattr(
        listing_tools._profile_cache,
        "get_entry",
        lambda key: listing_tools.CacheEntry(
            profiles=SAMPLE_PROFILES,
            timestamp=1234.0,
        ),
    )

    result = await listing_tools.refresh_profiles_cache()

    assert result["success"] is True
    assert result["total_count"] == 3
    assert result["stale"] is False
    assert result["cache_timestamp"] == 1234.0


@pytest.mark.asyncio
async def test_refresh_profiles_cache_stale(monkeypatch):
    monkeypatch.setattr(
        listing_tools,
        "_get_cache_key",
        lambda: ("identity-1", "na"),
    )
    monkeypatch.setattr(
        listing_tools,
        "_get_profiles_cached",
        AsyncMock(return_value=(SAMPLE_PROFILES, True)),
    )
    monkeypatch.setattr(
        listing_tools._profile_cache,
        "get_entry",
        lambda key: listing_tools.CacheEntry(
            profiles=SAMPLE_PROFILES,
            timestamp=900.0,
        ),
    )

    result = await listing_tools.refresh_profiles_cache()

    assert result["success"] is False
    assert result["stale"] is True
    assert result["cache_timestamp"] == 900.0
