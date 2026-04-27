"""Wire-path regression test: AuthenticatedClient against a real DSP spec.

PR #71's spec-contract tests (`tests/unit/test_accept_resolver_against_spec.py`)
prove the resolver picks the right Accept value for DSP multi-version operations
when given the right `accepts` list. This test proves the full pipeline:
real ``AuthenticatedClient`` → real ``MediaTypeRegistry`` populated from the
shipped ``dist/openapi/resources/AmazonDSPConversions.json`` → ``_inject_headers``
→ wire ``Accept`` value captured by intercepting ``httpx.AsyncClient.send``.

Without this test, CI has wire-path coverage only for SponsoredProducts
(via ``tests/unit/test_client_accept_resolver.py``); a regression on DSP
specifically — a different code path through the registry — could ship silently.

Auth is fully mocked (mirrors the ``test_client_accept_resolver.py`` pattern):
the test never reads env credentials and never touches the network. Stays
deterministic across machines and CI environments.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from amazon_ads_mcp.auth.base import BaseAmazonAdsProvider
from amazon_ads_mcp.auth.manager import AuthManager
from amazon_ads_mcp.utils.http_client import AuthenticatedClient
from amazon_ads_mcp.utils.media import MediaTypeRegistry

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DSP_CONVERSIONS_SPEC = (
    _REPO_ROOT / "dist" / "openapi" / "resources" / "AmazonDSPConversions.json"
)


@pytest.fixture
def dsp_conversions_registry() -> MediaTypeRegistry:
    if not _DSP_CONVERSIONS_SPEC.exists():
        pytest.skip(f"DSP Conversions spec not found at {_DSP_CONVERSIONS_SPEC}")
    with open(_DSP_CONVERSIONS_SPEC) as f:
        spec = json.load(f)
    reg = MediaTypeRegistry()
    reg.add_from_spec(spec)
    return reg


@pytest.fixture
def mocked_auth_manager() -> MagicMock:
    """Fully mocked auth manager — deterministic, no env credential reads.

    Mirrors the pattern in tests/unit/test_client_accept_resolver.py so the
    wire-path test stays consistent with the existing wire-path tests.
    Both manager and provider are spec'd so attribute typos and API renames
    fail at test time rather than producing silent child Mocks."""
    auth_manager = MagicMock(spec=AuthManager)
    auth_manager.get_headers = AsyncMock(
        return_value={
            "Authorization": "Bearer test",
            "Amazon-Advertising-API-ClientId": "test-client-id",
        }
    )
    auth_manager.provider = MagicMock(spec=BaseAmazonAdsProvider)
    auth_manager.provider.requires_identity_region_routing = MagicMock(
        return_value=False
    )
    auth_manager.provider.headers_are_identity_specific = MagicMock(
        return_value=False
    )
    auth_manager.provider.region_controlled_by_identity = MagicMock(
        return_value=False
    )
    auth_manager.provider.provider_type = "direct"
    auth_manager.get_active_identity = MagicMock(return_value=None)
    return auth_manager


@pytest.mark.asyncio
async def test_dsp_conversions_list_sends_v2_accept_on_wire(
    dsp_conversions_registry: MediaTypeRegistry,
    mocked_auth_manager: MagicMock,
) -> None:
    """`dspAmazonListConversionDefinitions` declares v1 and v2 in the spec.
    Resolver should pick v2 (the headline regression class). This test
    proves the v2 selection survives the full ``AuthenticatedClient.send``
    code path — not just the unit-level resolver call.

    If the resolver is removed, modified to pick v1 again, or if
    ``_inject_headers`` stops calling ``resolve_accept``, this test fails
    on the wire Accept value."""
    client = AuthenticatedClient(
        auth_manager=mocked_auth_manager,
        media_registry=dsp_conversions_registry,
    )
    request = client.build_request(
        "POST",
        "https://advertising-api.amazon.com/accounts/123/dsp/conversionDefinitions/list",
        json={},
    )
    captured: dict[str, str | None] = {}

    async def fake_send(self_, request_, **kwargs):
        captured["accept"] = request_.headers.get("Accept")
        return httpx.Response(200, request=request_)

    with patch.object(httpx.AsyncClient, "send", fake_send):
        await client.send(request)

    assert (
        captured.get("accept") == "application/vnd.dspconversiondefinition.v2+json"
    ), (
        f"DSP wire-path regression: expected v2 Accept, got "
        f"{captured.get('accept')!r}. Resolver may have regressed or "
        f"_inject_headers may no longer be calling resolve_accept."
    )


@pytest.mark.asyncio
async def test_dsp_conversions_caller_pinned_v1_preserved_on_wire(
    dsp_conversions_registry: MediaTypeRegistry,
    mocked_auth_manager: MagicMock,
) -> None:
    """A tool that explicitly pins ``Accept: …v1+json`` keeps v1 even when
    the resolver would auto-upgrade to v2. Resolver rule 1 (caller-pinned
    vendored is preserved unconditionally) must hold on the wire. This is
    the spec-driven escape hatch the design depends on for any operation
    where the algorithm picks wrong."""
    client = AuthenticatedClient(
        auth_manager=mocked_auth_manager,
        media_registry=dsp_conversions_registry,
    )
    pinned = "application/vnd.dspconversiondefinition.v1+json"
    request = client.build_request(
        "POST",
        "https://advertising-api.amazon.com/accounts/123/dsp/conversionDefinitions/list",
        headers={"Accept": pinned},
        json={},
    )
    captured: dict[str, str | None] = {}

    async def fake_send(self_, request_, **kwargs):
        captured["accept"] = request_.headers.get("Accept")
        return httpx.Response(200, request=request_)

    with patch.object(httpx.AsyncClient, "send", fake_send):
        await client.send(request)

    assert captured.get("accept") == pinned, (
        f"Caller-pinned vendored Accept was clobbered: expected {pinned!r}, "
        f"got {captured.get('accept')!r}. Resolver rule 1 may have regressed."
    )
