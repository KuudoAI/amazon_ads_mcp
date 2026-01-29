from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from amazon_ads_mcp.models import Identity, SetActiveIdentityRequest
from amazon_ads_mcp.tools import identity as identity_tools


@pytest.mark.asyncio
async def test_list_remote_identities_uses_provider(monkeypatch):
    identity = Identity(id="id-1", type="remote", attributes={})
    provider = SimpleNamespace(list_identities=AsyncMock(return_value=[identity]))
    manager = SimpleNamespace(provider=provider)
    monkeypatch.setattr(identity_tools, "get_auth_manager", lambda: manager)

    result = await identity_tools.list_remote_identities(identity_type="14")

    assert result.total == 1
    assert result.identities[0].id == "id-1"
    provider.list_identities.assert_awaited_once_with(identity_type="14")


@pytest.mark.asyncio
async def test_list_remote_identities_fallback(monkeypatch):
    identity = Identity(id="id-1", type="remote", attributes={})
    provider = SimpleNamespace()
    manager = SimpleNamespace(provider=provider, list_identities=AsyncMock(return_value=[identity]))
    monkeypatch.setattr(identity_tools, "get_auth_manager", lambda: manager)

    result = await identity_tools.list_remote_identities()

    assert result.total == 1
    assert result.identities[0].id == "id-1"
    manager.list_identities.assert_awaited_once()


@pytest.mark.asyncio
async def test_set_active_identity_success(monkeypatch):
    identity = Identity(id="id-1", type="remote", attributes={})
    manager = SimpleNamespace(
        set_active_identity=AsyncMock(return_value=identity),
        get_active_credentials=AsyncMock(return_value=None),
    )
    monkeypatch.setattr(identity_tools, "get_auth_manager", lambda: manager)

    result = await identity_tools.set_active_identity(SetActiveIdentityRequest(identity_id="id-1"))

    assert result.success is True
    assert result.credentials_loaded is True
    assert result.identity.id == "id-1"


@pytest.mark.asyncio
async def test_set_active_identity_credentials_failed(monkeypatch):
    identity = Identity(id="id-1", type="remote", attributes={})
    manager = SimpleNamespace(
        set_active_identity=AsyncMock(return_value=identity),
        get_active_credentials=AsyncMock(side_effect=RuntimeError("boom")),
    )
    monkeypatch.setattr(identity_tools, "get_auth_manager", lambda: manager)

    result = await identity_tools.set_active_identity(SetActiveIdentityRequest(identity_id="id-1"))

    assert result.success is True
    assert result.credentials_loaded is False
    assert "credentials not loaded" in (result.message or "")


@pytest.mark.asyncio
async def test_get_active_identity(monkeypatch):
    identity = Identity(id="id-1", type="remote", attributes={"name": "Test"})
    manager = SimpleNamespace(get_active_identity=MagicMock(return_value=identity))
    monkeypatch.setattr(identity_tools, "get_auth_manager", lambda: manager)

    result = await identity_tools.get_active_identity()

    assert result.id == "id-1"


@pytest.mark.asyncio
async def test_get_identity_info(monkeypatch):
    identity = Identity(id="id-1", type="remote", attributes={})
    manager = SimpleNamespace(get_identity=AsyncMock(return_value=identity))
    monkeypatch.setattr(identity_tools, "get_auth_manager", lambda: manager)

    result = await identity_tools.get_identity_info("id-1")

    assert result.id == "id-1"
