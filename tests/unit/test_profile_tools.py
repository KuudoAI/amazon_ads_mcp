from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from amazon_ads_mcp.tools import profile as profile_tools


@pytest.mark.asyncio
async def test_set_active_profile(monkeypatch):
    manager = SimpleNamespace(set_active_profile_id=MagicMock())
    monkeypatch.setattr(profile_tools, "get_auth_manager", lambda: manager)

    result = await profile_tools.set_active_profile("123")

    assert result["success"] is True
    assert result["profile_id"] == "123"
    manager.set_active_profile_id.assert_called_once_with("123")


@pytest.mark.asyncio
async def test_get_active_profile_with_profile(monkeypatch):
    manager = SimpleNamespace(
        get_active_profile_id=MagicMock(return_value="123"),
        get_profile_source=MagicMock(return_value="explicit"),
    )
    monkeypatch.setattr(profile_tools, "get_auth_manager", lambda: manager)

    result = await profile_tools.get_active_profile()

    assert result["success"] is True
    assert result["profile_id"] == "123"
    assert result["source"] == "explicit"


@pytest.mark.asyncio
async def test_get_active_profile_missing(monkeypatch):
    manager = SimpleNamespace(get_active_profile_id=MagicMock(return_value=None))
    monkeypatch.setattr(profile_tools, "get_auth_manager", lambda: manager)

    result = await profile_tools.get_active_profile()

    assert result["success"] is True
    assert result["profile_id"] is None


@pytest.mark.asyncio
async def test_clear_active_profile_with_fallback(monkeypatch):
    manager = SimpleNamespace(
        clear_active_profile_id=MagicMock(),
        get_active_profile_id=MagicMock(return_value="fallback"),
    )
    monkeypatch.setattr(profile_tools, "get_auth_manager", lambda: manager)

    result = await profile_tools.clear_active_profile()

    assert result["success"] is True
    assert result["fallback_profile_id"] == "fallback"


@pytest.mark.asyncio
async def test_clear_active_profile_no_fallback(monkeypatch):
    manager = SimpleNamespace(
        clear_active_profile_id=MagicMock(),
        get_active_profile_id=MagicMock(return_value=None),
    )
    monkeypatch.setattr(profile_tools, "get_auth_manager", lambda: manager)

    result = await profile_tools.clear_active_profile()

    assert result["success"] is True
    assert "no fallback" in result["message"]
