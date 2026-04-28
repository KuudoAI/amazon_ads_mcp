"""Live drift detector: profiles endpoint contract.

Hits the real Amazon Ads ``/v2/profiles`` endpoint via a sandbox account
and verifies the response shape we depend on. Catches schema drift early
— if Amazon renames a field or adds a required one, this test fails
within a week and we can update before the change ripples into customer
deployments.

This is the **reference test** for the live lane. New live tests should
follow the same shape:

1. ``@pytest.mark.live`` — gates on ``RUN_LIVE_TESTS=1``.
2. Per-test credential check via ``pytest.skip`` — runs cleanly even if
   only some sandbox credentials are configured.
3. Asserts on **contract shape**, not specific values. We don't assert
   "profile X has campaignId Y"; we assert "every profile dict has the
   keys our code reads."
4. Documents the sandbox state assumed (e.g., "at least one profile
   must exist on the configured account").

Running:

    export RUN_LIVE_TESTS=1
    export AMAZON_AD_API_CLIENT_ID=...
    export AMAZON_AD_API_CLIENT_SECRET=...
    export AMAZON_AD_API_REFRESH_TOKEN=...   # sandbox refresh token
    uv run pytest tests/live/ -v
"""

from __future__ import annotations

import os

import pytest

# Module-level marker — every test in this file gets ``live``.
pytestmark = pytest.mark.live


def _require_direct_credentials() -> None:
    """Skip if direct-auth sandbox credentials are not configured."""
    required = (
        "AMAZON_AD_API_CLIENT_ID",
        "AMAZON_AD_API_CLIENT_SECRET",
        "AMAZON_AD_API_REFRESH_TOKEN",
    )
    missing = [v for v in required if not os.environ.get(v)]
    if missing:
        pytest.skip(
            f"live test requires sandbox credentials; missing: {', '.join(missing)}"
        )


# --- Profiles endpoint contract ------------------------------------------


@pytest.mark.asyncio
async def test_list_profiles_returns_documented_shape() -> None:
    """``/v2/profiles`` response items have the keys our tools read.

    Schema-drift canary: if Amazon adds/renames/removes any of these
    keys, this test fails within a week of the deploy. The keys checked
    are the documented ones our profile-listing tools depend on.
    """
    _require_direct_credentials()

    from amazon_ads_mcp.auth.manager import AuthManager
    from amazon_ads_mcp.utils.http_client import AuthenticatedClient

    AuthManager.reset()  # avoid singleton pollution from earlier tests
    client = AuthenticatedClient()

    try:
        response = await client.get(
            "https://advertising-api.amazon.com/v2/profiles"
        )
    finally:
        await client.aclose()

    assert response.status_code == 200, (
        f"sandbox profiles endpoint returned {response.status_code}; "
        f"check sandbox account state and credentials"
    )
    profiles = response.json()
    assert isinstance(profiles, list), (
        f"expected list of profiles, got {type(profiles).__name__}: {profiles!r}"
    )
    assert len(profiles) > 0, (
        "sandbox account has no profiles — test cannot validate shape; "
        "ensure the sandbox account has at least one profile configured"
    )

    # Contract check — fail loudly if any profile is missing keys our
    # tools read. Don't assert specific values; assert shape only.
    required_keys = {"profileId", "countryCode", "currencyCode", "accountInfo"}
    for i, prof in enumerate(profiles):
        missing = required_keys - prof.keys()
        assert not missing, (
            f"profile #{i} missing required keys: {missing}. "
            f"Got keys: {sorted(prof.keys())}. "
            f"Schema may have drifted; update tools/profile_listing.py "
            f"and tools/profile.py if Amazon renamed/removed fields."
        )

    # accountInfo nested contract
    account_keys = {"id", "type"}
    for i, prof in enumerate(profiles):
        ai = prof["accountInfo"]
        missing = account_keys - ai.keys()
        assert not missing, (
            f"profile #{i} accountInfo missing: {missing}. "
            f"Got: {sorted(ai.keys())}"
        )


@pytest.mark.asyncio
async def test_oauth_token_refresh_returns_valid_access_token() -> None:
    """The OAuth refresh-token endpoint accepts our sandbox refresh token
    and returns an access token in the documented shape.

    Catches: refresh-token rotation, OAuth endpoint changes, scope
    requirement drift.
    """
    _require_direct_credentials()

    from amazon_ads_mcp.auth.base import ProviderConfig
    from amazon_ads_mcp.auth.providers.direct import DirectAmazonAdsProvider

    provider = DirectAmazonAdsProvider(
        ProviderConfig(
            client_id=os.environ["AMAZON_AD_API_CLIENT_ID"],
            client_secret=os.environ["AMAZON_AD_API_CLIENT_SECRET"],
            refresh_token=os.environ["AMAZON_AD_API_REFRESH_TOKEN"],
            region="na",
        )
    )
    try:
        token = await provider.get_token()
    finally:
        await provider.close()

    assert token is not None
    assert token.value, "access_token field is empty"
    assert token.token_type.lower() == "bearer"
    assert token.expires_at is not None, (
        "OAuth response did not include an expiration; tokens without "
        "expiry would never refresh and would silently fail when stale"
    )
