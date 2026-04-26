"""Profile listing tools with server-side caching and bounded responses."""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..auth.manager import get_auth_manager
from ..config.settings import Settings
from ..utils.errors import ValidationError
from ..utils.http import get_http_client

logger = logging.getLogger(__name__)


DEFAULT_CACHE_TTL_SECONDS = int(os.getenv("AMAZON_ADS_PROFILE_CACHE_TTL", "300"))
MAX_SEARCH_LIMIT = 50
DEFAULT_SEARCH_LIMIT = 50
MAX_PAGE_LIMIT = 100
DEFAULT_PAGE_LIMIT = 100
PROFILE_SELECTION_THRESHOLD = 50


@dataclass
class CacheEntry:
    profiles: List[Dict[str, Any]]
    timestamp: float


class ProfileCache:
    """In-memory profile cache scoped by identity and region."""

    def __init__(self, ttl_seconds: int = DEFAULT_CACHE_TTL_SECONDS) -> None:
        self._cache: Dict[Tuple[str, str], CacheEntry] = {}
        self._ttl_seconds = ttl_seconds

    def _is_expired(self, entry: CacheEntry, now: float) -> bool:
        return (now - entry.timestamp) > self._ttl_seconds

    async def get_profiles(
        self,
        key: Tuple[str, str],
        fetcher: Callable[[], Any],
        force_refresh: bool = False,
    ) -> Tuple[List[Dict[str, Any]], bool]:
        now = time.time()
        entry = self._cache.get(key)

        if entry and not force_refresh and not self._is_expired(entry, now):
            return entry.profiles, False

        try:
            profiles = await fetcher()
            self._cache[key] = CacheEntry(profiles=profiles, timestamp=now)
            return profiles, False
        except Exception as exc:
            if entry:
                logger.warning("Using stale profile cache for %s: %s", key, exc)
                return entry.profiles, True
            raise

    def clear(self, key: Tuple[str, str]) -> None:
        self._cache.pop(key, None)

    def get_entry(self, key: Tuple[str, str]) -> Optional[CacheEntry]:
        return self._cache.get(key)


_profile_cache = ProfileCache()


def _get_cache_key() -> Tuple[str, str]:
    auth_manager = get_auth_manager()
    identity_id = auth_manager.get_active_identity_id() or "default"
    region = auth_manager.get_active_region() or Settings().amazon_ads_region
    return identity_id, region


def _apply_limit(
    limit: Optional[int], default: int, max_limit: int
) -> Tuple[int, Optional[str]]:
    """Validate ``limit`` and return (effective_limit, optional_cap_message).

    - ``None`` → returns ``(default, None)``.
    - Non-integer / non-positive → raises :class:`ValidationError` so the
      envelope translator classifies as ``mcp_input_validation`` (previously
      these silently fell back to the default, masking caller mistakes).
    - Over-cap → returns ``(max_limit, "limit clamped from N to maximum M")``
      so callers see the cap rather than getting a smaller-than-expected page
      with no explanation.
    """
    if limit is None:
        return default, None
    try:
        value = int(limit)
    except (TypeError, ValueError):
        err = ValidationError(
            f"limit must be an integer, got {limit!r}",
            field="limit",
        )
        err.details["error_code"] = "INVALID_LIMIT"
        raise err
    if value <= 0:
        err = ValidationError(
            f"limit must be > 0, got {value}",
            field="limit",
        )
        err.details["error_code"] = "INVALID_LIMIT"
        raise err
    if value > max_limit:
        return max_limit, f"limit clamped from {value} to maximum {max_limit}"
    return value, None


def _compose_message(*parts: Optional[str]) -> Optional[str]:
    """Join non-empty message parts with a single space; return None if all empty."""
    kept = [p for p in parts if p]
    return " ".join(kept) if kept else None


def _normalize_profile(profile: Dict[str, Any]) -> Dict[str, str]:
    account_info = profile.get("accountInfo") or {}
    return {
        "profile_id": str(profile.get("profileId", "")),
        "name": str(account_info.get("name", "")),
        "country_code": str(profile.get("countryCode", "")),
        "type": str(account_info.get("type", "")),
    }


def _matches_filters(
    profile: Dict[str, Any],
    query: Optional[str],
    country_code: Optional[str],
    account_type: Optional[str],
) -> bool:
    if country_code:
        if str(profile.get("countryCode", "")).upper() != country_code.upper():
            return False

    if account_type:
        p_type = (profile.get("accountInfo") or {}).get("type", "")
        if str(p_type).lower() != account_type.lower():
            return False

    if query:
        q = query.lower()
        name = (profile.get("accountInfo") or {}).get("name", "")
        profile_id = str(profile.get("profileId", "")).lower()
        if q not in str(name).lower() and q not in profile_id:
            return False

    return True


async def _fetch_profiles() -> List[Dict[str, Any]]:
    auth_manager = get_auth_manager()
    credentials = await auth_manager.get_active_credentials()
    base_url = credentials.base_url or Settings().region_endpoint
    client = await get_http_client(
        authenticated=True,
        auth_manager=auth_manager,
        base_url=base_url,
    )
    response = await client.get("/v2/profiles")
    response.raise_for_status()
    data = response.json()
    return data if isinstance(data, list) else []


async def _get_profiles_cached(force_refresh: bool = False) -> Tuple[List[Dict[str, Any]], bool]:
    key = _get_cache_key()
    return await _profile_cache.get_profiles(key, _fetch_profiles, force_refresh=force_refresh)


async def get_profiles_cached(
    force_refresh: bool = False,
) -> Tuple[List[Dict[str, Any]], bool]:
    """Public wrapper for fetching cached profiles."""
    return await _get_profiles_cached(force_refresh=force_refresh)

async def summarize_profiles() -> Dict[str, Any]:
    profiles, stale = await _get_profiles_cached()

    by_country: Dict[str, int] = {}
    by_type: Dict[str, int] = {}
    for profile in profiles:
        country = str(profile.get("countryCode", ""))
        account_type = str((profile.get("accountInfo") or {}).get("type", ""))
        if country:
            by_country[country] = by_country.get(country, 0) + 1
        if account_type:
            by_type[account_type] = by_type.get(account_type, 0) + 1

    message = "Ask for a country or advertiser name to narrow results."
    if stale:
        message = "Using cached profile list; data may be stale."

    return {
        "total_count": len(profiles),
        "by_country": by_country,
        "by_type": by_type,
        "message": message,
        "stale": stale,
    }


async def search_profiles(
    query: Optional[str] = None,
    country_code: Optional[str] = None,
    account_type: Optional[str] = None,
    limit: Optional[int] = None,
) -> Dict[str, Any]:
    profiles, stale = await _get_profiles_cached()
    filtered = [
        profile
        for profile in profiles
        if _matches_filters(profile, query, country_code, account_type)
    ]

    limit_value, cap_msg = _apply_limit(limit, DEFAULT_SEARCH_LIMIT, MAX_SEARCH_LIMIT)
    items = [_normalize_profile(profile) for profile in filtered[:limit_value]]

    stale_msg = "Using cached profile list; data may be stale." if stale else None
    # R3: pagination guidance — appended ONLY when the request actually
    # exceeded the cap (cap_msg signals over-cap clamping). A normal
    # 50-result call where total > 50 (has_more=true) does NOT get this
    # noisy guidance — the caller asked for 50 and got 50; the has_more
    # flag is the signal. This avoids false-positive nudges per reviewer
    # feedback.
    pagination_msg = (
        "search_profiles is bounded; use page_profiles to paginate beyond "
        f"{MAX_SEARCH_LIMIT} results."
        if cap_msg
        else None
    )
    message = _compose_message(stale_msg, cap_msg, pagination_msg)

    total_count = len(filtered)
    returned_count = len(items)
    return {
        "items": items,
        "total_count": total_count,
        "returned_count": returned_count,
        "has_more": returned_count < total_count,
        "message": message,
        "stale": stale,
    }


async def page_profiles(
    country_code: Optional[str] = None,
    account_type: Optional[str] = None,
    offset: int = 0,
    limit: Optional[int] = None,
) -> Dict[str, Any]:
    profiles, stale = await _get_profiles_cached()
    filtered = [
        profile
        for profile in profiles
        if _matches_filters(profile, None, country_code, account_type)
    ]

    limit_value, cap_msg = _apply_limit(limit, DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT)
    try:
        offset_value = int(offset)
    except (TypeError, ValueError):
        offset_value = 0
    offset_value = max(0, offset_value)
    page = filtered[offset_value : offset_value + limit_value]
    items = [_normalize_profile(profile) for profile in page]

    stale_msg = "Using cached profile list; data may be stale." if stale else None
    message = _compose_message(stale_msg, cap_msg)

    total_count = len(filtered)
    returned_count = len(items)
    has_more = (offset_value + returned_count) < total_count
    next_offset = offset_value + returned_count if has_more else None

    return {
        "items": items,
        "total_count": total_count,
        "returned_count": returned_count,
        "has_more": has_more,
        "next_offset": next_offset,
        "message": message,
        "stale": stale,
    }


async def refresh_profiles_cache() -> Dict[str, Any]:
    """Force refresh the cached profile list for the current identity and region."""
    key = _get_cache_key()
    try:
        profiles, stale = await _get_profiles_cached(force_refresh=True)
    except Exception as exc:
        return {
            "success": False,
            "total_count": 0,
            "cache_timestamp": None,
            "message": f"Failed to refresh profiles: {exc}",
            "stale": False,
        }

    entry = _profile_cache.get_entry(key)
    cache_timestamp = entry.timestamp if entry else None
    if stale:
        return {
            "success": False,
            "total_count": len(profiles),
            "cache_timestamp": cache_timestamp,
            "message": "Refresh failed; using cached profile list.",
            "stale": True,
        }

    return {
        "success": True,
        "total_count": len(profiles),
        "cache_timestamp": cache_timestamp,
        "message": "Profile cache refreshed.",
        "stale": False,
    }
