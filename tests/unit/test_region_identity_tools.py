from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from amazon_ads_mcp.models import Identity, SetActiveIdentityResponse
from amazon_ads_mcp.tools import identity as identity_tools
from amazon_ads_mcp.tools import region_identity


@pytest.mark.asyncio
async def test_list_identities_by_region(monkeypatch):
    identities = [
        Identity(id="id-na", type="remote", attributes={"region": "na", "name": "NA"}),
        Identity(id="id-eu", type="remote", attributes={"region": "eu", "name": "EU"}),
    ]
    provider = SimpleNamespace(list_identities=AsyncMock(return_value=identities))
    manager = SimpleNamespace(provider=provider, get_active_identity=lambda: identities[0])
    monkeypatch.setattr(region_identity, "get_auth_manager", lambda: manager)

    result = await region_identity.list_identities_by_region()

    assert result["totals"]["na"] == 1
    assert result["totals"]["eu"] == 1
    assert result["current_identity"] == "id-na"


@pytest.mark.asyncio
async def test_list_identities_by_region_filter(monkeypatch):
    identities = [
        Identity(id="id-na", type="remote", attributes={"region": "na", "name": "NA"}),
        Identity(id="id-eu", type="remote", attributes={"region": "eu", "name": "EU"}),
    ]
    provider = SimpleNamespace(list_identities=AsyncMock(return_value=identities))
    manager = SimpleNamespace(provider=provider, get_active_identity=lambda: None)
    monkeypatch.setattr(region_identity, "get_auth_manager", lambda: manager)

    result = await region_identity.list_identities_by_region("eu")

    assert result["total"] == 1
    assert result["eu"][0]["id"] == "id-eu"


@pytest.mark.asyncio
async def test_switch_to_region_identity_invalid_region():
    result = await region_identity.switch_to_region_identity("xx")

    assert result["success"] is False
    assert result["error"] == "INVALID_REGION"


@pytest.mark.asyncio
async def test_switch_to_region_identity_no_identities(monkeypatch):
    monkeypatch.setattr(region_identity, "list_identities_by_region", AsyncMock(return_value={"na": []}))

    result = await region_identity.switch_to_region_identity("na")

    assert result["success"] is False
    assert result["error"] == "NO_IDENTITIES"


@pytest.mark.asyncio
async def test_switch_to_region_identity_not_in_region(monkeypatch):
    monkeypatch.setattr(
        region_identity,
        "list_identities_by_region",
        AsyncMock(return_value={"na": [{"id": "id-1", "name": "NA"}]}),
    )

    result = await region_identity.switch_to_region_identity("na", identity_id="id-2")

    assert result["success"] is False
    assert result["error"] == "IDENTITY_NOT_IN_REGION"


@pytest.mark.asyncio
async def test_switch_to_region_identity_success(monkeypatch):
    monkeypatch.setattr(
        region_identity,
        "list_identities_by_region",
        AsyncMock(return_value={"na": [{"id": "id-1", "name": "NA"}]}),
    )

    response = SetActiveIdentityResponse(
        success=True,
        identity=Identity(id="id-1", type="remote", attributes={}),
        credentials_loaded=True,
    )
    monkeypatch.setattr(identity_tools, "set_active_identity", AsyncMock(return_value=response))

    result = await region_identity.switch_to_region_identity("na")

    assert result["success"] is True
    assert result["identity"]["id"] == "id-1"
    assert result["credentials_loaded"] is True
