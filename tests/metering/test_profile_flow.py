"""§8.3 "Profile flow": `tools/profile_listing._fetch_profiles` produces
exactly one `/v2/profiles` usage event per real upstream call, and a
repeat call served from `ProfileCache` (this repo DOES have a cache layer
-- `tools/profile_listing.ProfileCache`, keyed by (identity, region) --
so the §8.3 cache-hit bullet is exercised directly here, not documented
N/A) produces no second event.

Drives `_fetch_profiles` for real (the second construction path:
`get_http_client(authenticated=True, ...)` ->
`HTTPClientManager.get_client(client_class=AuthenticatedClient)`), with
only the ONE network-touching seam (`profile_listing.get_http_client`)
replaced by an equivalent that still constructs a REAL
`AuthenticatedClient` (so the real transport-wrap runs) over a
MockTransport standing in for the real Amazon Ads API -- "smallest
driveable wrapper" per the brief, since `_fetch_profiles` itself exposes
no transport-injection seam and this task must not modify its production
code.
"""

from __future__ import annotations

import asyncio
import sys
from types import SimpleNamespace

import httpx
import pytest

pytestmark = pytest.mark.skipif(
    sys.version_info < (3, 12), reason="metering requires Python>=3.12"
)

if sys.version_info >= (3, 12):
    from amazon_ads_mcp.metering.adapter import set_metering_runtime
    from amazon_ads_mcp.tools import profile_listing
    from amazon_ads_mcp.utils.http_client import AuthenticatedClient

    from ._support import ALLOWED_HOST, RecordingIngestTransport, build_runtime


class _FakeProfileAuthManager:
    """Enough of the `AuthManager` surface for `_fetch_profiles` and
    `_get_cache_key` -- no real provider, no real network."""

    provider = None

    def __init__(self, identity_id: str = "identity-profiles-1", region: str = "na") -> None:
        self._identity_id = identity_id
        self._region = region

    async def get_active_credentials(self) -> SimpleNamespace:
        return SimpleNamespace(base_url=f"https://{ALLOWED_HOST}")

    async def get_headers(self) -> dict:
        return {
            "Authorization": "Bearer conformance-test-token",
            "Amazon-Advertising-API-ClientId": "conformance-test-client-id",
        }

    def get_active_identity_id(self):
        return self._identity_id

    def get_active_region(self):
        return self._region


def _profiles_payload() -> list:
    return [
        {
            "profileId": 1,
            "countryCode": "US",
            "accountInfo": {"name": "Acme Ads", "type": "seller"},
        }
    ]


def test_fetch_profiles_emits_one_event_then_cache_hit_emits_none(tmp_path, monkeypatch) -> None:
    async def scenario():
        ingest = RecordingIngestTransport()
        runtime = await build_runtime(tmp_path, ingest=ingest)
        set_metering_runtime(runtime)

        upstream_calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            upstream_calls["n"] += 1
            assert request.url.path == "/v2/profiles"
            return httpx.Response(200, json=_profiles_payload())

        upstream = httpx.MockTransport(handler)

        async def fake_get_http_client(*, authenticated, auth_manager, base_url, **_ignored):
            # Same real construction path (AuthenticatedClient.__init__,
            # which installs the metered transport) -- only the network
            # socket is replaced.
            return AuthenticatedClient(transport=upstream, auth_manager=auth_manager, base_url=base_url)

        fake_auth_manager = _FakeProfileAuthManager()
        monkeypatch.setattr(profile_listing, "get_http_client", fake_get_http_client)
        monkeypatch.setattr(profile_listing, "get_auth_manager", lambda: fake_auth_manager)
        profile_listing._profile_cache.clear(profile_listing._get_cache_key())

        try:
            # First call (via the cached wrapper -- the real call shape
            # every tool uses; an empty cache means it drives
            # `_fetch_profiles` as its fetcher): a real upstream hit, one
            # usage event.
            profiles, stale = await profile_listing._get_profiles_cached()
            assert profiles == _profiles_payload()
            assert stale is False
            assert upstream_calls["n"] == 1

            events = await ingest.wait_for_event_count(1)
            assert len(events) == 1
            assert events[0]["data"]["url.path"] == "/v2/profiles"

            # Second call through the cached wrapper, same identity/region
            # key, within TTL: served from ProfileCache -- no second
            # upstream call, no second event.
            cached_profiles, stale = await profile_listing._get_profiles_cached()
            assert cached_profiles == _profiles_payload()
            assert stale is False
            assert upstream_calls["n"] == 1  # still just the one real call

            # Give the (idle) flusher a beat -- there is nothing new to
            # flush, so the event count must stay at 1.
            await asyncio.sleep(0.05)
            assert len(ingest.events()) == 1
        finally:
            set_metering_runtime(None)
            await runtime.aclose()

    asyncio.run(scenario())
