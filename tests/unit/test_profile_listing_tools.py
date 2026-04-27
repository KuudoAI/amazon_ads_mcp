from unittest.mock import AsyncMock

import pytest

from amazon_ads_mcp.tools import profile_listing as listing_tools
from amazon_ads_mcp.utils.errors import ErrorCategory, ValidationError


def _spec_cached_fetcher(return_value):
    """Build an AsyncMock spec'd against the real ``_get_profiles_cached``.

    Signature drift in the production fetcher (e.g., a renamed kwarg) will
    surface here as a TypeError at the call site instead of silently passing.
    """
    return AsyncMock(spec=listing_tools._get_profiles_cached, return_value=return_value)


# ---------------------------------------------------------------------------
# _apply_limit — typed validation errors for non-positive, cap message for over-cap
# ---------------------------------------------------------------------------


def test_apply_limit_default_when_none():
    """Regression: limit=None still returns the default with no message."""
    assert listing_tools._apply_limit(None, 50, 50) == (50, None)


def test_apply_limit_within_bounds():
    """Regression: a valid limit ≤ max returns (limit, None)."""
    assert listing_tools._apply_limit(25, 50, 50) == (25, None)


def test_apply_limit_zero_raises_validation_error():
    """limit=0 must raise typed ValidationError, not silently default."""
    with pytest.raises(ValidationError) as excinfo:
        listing_tools._apply_limit(0, 50, 50)
    assert excinfo.value.category == ErrorCategory.VALIDATION


def test_apply_limit_negative_raises_validation_error():
    """limit=-5 must raise typed ValidationError, not silently default."""
    with pytest.raises(ValidationError) as excinfo:
        listing_tools._apply_limit(-5, 50, 50)
    assert excinfo.value.category == ErrorCategory.VALIDATION
    assert "must be > 0" in str(excinfo.value).lower() or ">" in str(excinfo.value)


def test_apply_limit_non_integer_raises_validation_error():
    """Non-numeric limit must raise typed ValidationError."""
    with pytest.raises(ValidationError):
        listing_tools._apply_limit("not-a-number", 50, 50)


def test_apply_limit_over_cap_returns_clamped_with_message():
    """limit > max returns (max, cap_message). Cap message describes the clamp."""
    effective, msg = listing_tools._apply_limit(200, 50, 50)
    assert effective == 50
    assert msg is not None
    assert "200" in msg and "50" in msg


# ---------------------------------------------------------------------------
# search_profiles — over-cap surfaces the cap notice on the existing message field
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_search_profiles_over_cap_includes_cap_notice_in_message(monkeypatch):
    """Wire-shape regression: when limit > MAX_SEARCH_LIMIT, the response's
    `message` field surfaces the cap notice (no new field added)."""
    big_profiles = [
        {"profileId": i, "accountInfo": {"name": f"acc-{i}", "type": "seller"}}
        for i in range(100)
    ]
    monkeypatch.setattr(
        listing_tools,
        "_get_profiles_cached",
        _spec_cached_fetcher((big_profiles, False)),
    )

    result = await listing_tools.search_profiles(limit=200)

    assert result["returned_count"] == listing_tools.MAX_SEARCH_LIMIT
    assert result["message"] is not None
    assert "200" in result["message"] and "50" in result["message"]


@pytest.mark.asyncio
async def test_search_profiles_over_cap_with_stale_message_combines_both(monkeypatch):
    """When both stale-cache AND cap notices apply, the message contains both."""
    big_profiles = [
        {"profileId": i, "accountInfo": {"name": f"acc-{i}", "type": "seller"}}
        for i in range(100)
    ]
    monkeypatch.setattr(
        listing_tools,
        "_get_profiles_cached",
        _spec_cached_fetcher((big_profiles, True)),  # stale=True
    )

    result = await listing_tools.search_profiles(limit=200)

    assert result["stale"] is True
    msg = result["message"]
    assert "stale" in msg.lower(), f"missing stale notice in {msg!r}"
    assert "clamped" in msg.lower() or "200" in msg, f"missing cap notice in {msg!r}"


@pytest.mark.asyncio
async def test_search_profiles_negative_limit_raises_through_tool(monkeypatch):
    """Negative limit surfaces as ValidationError from search_profiles."""
    monkeypatch.setattr(
        listing_tools,
        "_get_profiles_cached",
        _spec_cached_fetcher(([], False)),
    )

    with pytest.raises(ValidationError):
        await listing_tools.search_profiles(limit=-5)


@pytest.mark.asyncio
async def test_search_profiles_over_cap_includes_pagination_guidance(monkeypatch):
    """R3: when limit > MAX_SEARCH_LIMIT, the response message includes
    explicit guidance to use page_profiles for paginating beyond the cap."""
    big_profiles = [
        {"profileId": i, "accountInfo": {"name": f"acc-{i}", "type": "seller"}}
        for i in range(100)
    ]
    monkeypatch.setattr(
        listing_tools,
        "_get_profiles_cached",
        _spec_cached_fetcher((big_profiles, False)),
    )

    result = await listing_tools.search_profiles(limit=200)

    assert result["returned_count"] == listing_tools.MAX_SEARCH_LIMIT
    msg = result["message"]
    assert "page_profiles" in msg, (
        f"expected pagination guidance in over-cap message, got {msg!r}"
    )
    assert "paginate" in msg.lower() or "beyond" in msg.lower()


@pytest.mark.asyncio
async def test_search_profiles_normal_50_call_no_pagination_guidance(monkeypatch):
    """R3 narrowing per reviewer feedback: a normal at-cap call (user
    asked for 50, total is more, has_more=true) does NOT get the noisy
    pagination nudge. Guidance fires ONLY when the cap actually clamped
    the request (i.e. limit > 50). Avoids false-positive nudges."""
    big_profiles = [
        {"profileId": i, "accountInfo": {"name": f"acc-{i}", "type": "seller"}}
        for i in range(88)
    ]
    monkeypatch.setattr(
        listing_tools,
        "_get_profiles_cached",
        _spec_cached_fetcher((big_profiles, False)),
    )

    result = await listing_tools.search_profiles(limit=50)
    assert result["returned_count"] == 50
    assert result["has_more"] is True  # 50 < 88
    # Critical: no pagination guidance. Caller asked for 50, got 50.
    msg = result["message"] or ""
    assert "page_profiles" not in msg, (
        f"unexpected pagination nudge for at-cap call (no clamp): {msg!r}"
    )


@pytest.mark.asyncio
async def test_search_profiles_default_limit_no_pagination_guidance(monkeypatch):
    """R3: omitting limit (uses default of 50) also doesn't trigger
    pagination guidance. Same reasoning as the explicit-50 case."""
    big_profiles = [
        {"profileId": i, "accountInfo": {"name": f"acc-{i}", "type": "seller"}}
        for i in range(88)
    ]
    monkeypatch.setattr(
        listing_tools,
        "_get_profiles_cached",
        _spec_cached_fetcher((big_profiles, False)),
    )

    result = await listing_tools.search_profiles()
    assert result["returned_count"] == 50
    msg = result["message"] or ""
    assert "page_profiles" not in msg


@pytest.mark.asyncio
async def test_page_profiles_over_cap_includes_cap_notice(monkeypatch):
    """Same cap-message contract on page_profiles (uses MAX_PAGE_LIMIT=100)."""
    big_profiles = [
        {"profileId": i, "accountInfo": {"name": f"acc-{i}", "type": "seller"}}
        for i in range(200)
    ]
    monkeypatch.setattr(
        listing_tools,
        "_get_profiles_cached",
        _spec_cached_fetcher((big_profiles, False)),
    )

    result = await listing_tools.page_profiles(limit=500)
    assert result["returned_count"] == listing_tools.MAX_PAGE_LIMIT
    assert result["message"] is not None
    assert "500" in result["message"] and "100" in result["message"]


@pytest.mark.asyncio
async def test_page_profiles_negative_limit_raises(monkeypatch):
    """page_profiles also rejects negative limits."""
    monkeypatch.setattr(
        listing_tools,
        "_get_profiles_cached",
        _spec_cached_fetcher(([], False)),
    )

    with pytest.raises(ValidationError):
        await listing_tools.page_profiles(limit=-5)


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
        _spec_cached_fetcher((SAMPLE_PROFILES, False)),
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
        _spec_cached_fetcher((SAMPLE_PROFILES, False)),
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
        _spec_cached_fetcher((SAMPLE_PROFILES, False)),
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
        _spec_cached_fetcher((SAMPLE_PROFILES, False)),
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
        _spec_cached_fetcher((SAMPLE_PROFILES, True)),
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
