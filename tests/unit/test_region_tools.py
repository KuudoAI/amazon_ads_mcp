import pytest

from amazon_ads_mcp.models import Identity
from amazon_ads_mcp.tools import region as region_tools


class DirectProvider:
    def __init__(self, region="na"):
        self._region = region
        self._access_token = "token"

    @property
    def region(self):
        return self._region

    def region_controlled_by_identity(self):
        return False

    def get_region_endpoint(self, region=None):
        return f"https://api.{region or self._region}.example.com"

    def get_oauth_endpoint(self, region=None):
        return f"https://oauth.{region or self._region}.example.com"


class OpenBridgeProvider:
    def __init__(self, region="na"):
        self._region = region

    @property
    def region(self):
        return self._region

    def get_region_endpoint(self, region=None):
        return f"https://api.{region or self._region}.example.com"


class IdentityControlledProvider:
    def __init__(self, provider_type="openbridge"):
        self.provider_type = provider_type

    def region_controlled_by_identity(self):
        return True


class DummyAuthManager:
    def __init__(self, provider, identity=None, identity_region=None):
        self.provider = provider
        self._identity = identity
        self._identity_region = identity_region

    def get_active_identity(self):
        return self._identity

    def get_active_region(self):
        return self._identity_region


@pytest.mark.asyncio
async def test_set_active_region_invalid(monkeypatch):
    monkeypatch.setattr(region_tools, "get_auth_manager", lambda: DummyAuthManager(DirectProvider()))

    with pytest.raises(ValueError):
        await region_tools.set_active_region("xx")


@pytest.mark.asyncio
async def test_set_active_region_identity_mismatch(monkeypatch):
    identity = Identity(id="id-1", type="remote", attributes={"region": "na", "name": "NA"})
    manager = DummyAuthManager(IdentityControlledProvider(), identity=identity)
    monkeypatch.setattr(region_tools, "get_auth_manager", lambda: manager)

    result = await region_tools.set_active_region("eu")

    assert result["success"] is False
    assert result["error"] == "REGION_MISMATCH"
    assert result["identity_region"] == "na"


@pytest.mark.asyncio
async def test_set_active_region_identity_match(monkeypatch):
    identity = Identity(id="id-1", type="remote", attributes={"region": "na", "name": "NA"})
    manager = DummyAuthManager(IdentityControlledProvider(), identity=identity)
    monkeypatch.setattr(region_tools, "get_auth_manager", lambda: manager)

    result = await region_tools.set_active_region("na")

    assert result["success"] is True
    assert result["region"] == "na"


@pytest.mark.asyncio
async def test_set_active_region_direct_updates_provider(monkeypatch):
    provider = DirectProvider(region="na")
    manager = DummyAuthManager(provider)
    monkeypatch.setattr(region_tools, "get_auth_manager", lambda: manager)

    result = await region_tools.set_active_region("eu")

    assert result["success"] is True
    assert result["previous_region"] == "na"
    assert result["new_region"] == "eu"
    assert provider._region == "eu"
    assert provider._access_token is None
    assert result["api_endpoint"] == "https://api.eu.example.com"
    assert result["oauth_endpoint"] == "https://oauth.eu.example.com"


@pytest.mark.asyncio
async def test_get_active_region_openbridge(monkeypatch):
    provider = OpenBridgeProvider(region="na")
    identity = Identity(id="id-1", type="remote", attributes={"region": "na"})
    manager = DummyAuthManager(provider, identity=identity, identity_region="na")
    monkeypatch.setattr(region_tools, "get_auth_manager", lambda: manager)

    result = await region_tools.get_active_region()

    assert result["region"] == "na"
    assert result["auth_method"] == "openbridge"
    assert result["source"] == "identity"


@pytest.mark.asyncio
async def test_list_available_regions_sandbox(monkeypatch):
    provider = DirectProvider(region="na")
    manager = DummyAuthManager(provider)
    monkeypatch.setattr(region_tools, "get_auth_manager", lambda: manager)
    monkeypatch.setenv("AMAZON_ADS_SANDBOX_MODE", "true")

    result = await region_tools.list_available_regions()

    assert result["sandbox_mode"] is True
    assert "advertising-api-test" in result["regions"]["na"]["api_endpoint"]
