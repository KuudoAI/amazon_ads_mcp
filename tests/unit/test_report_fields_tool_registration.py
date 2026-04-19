"""Tests for report_fields tool registration in the FastMCP server.

Locked contract (adsv1.md §E.2):
- After registration, server.list_tools() contains `report_fields`.
- Tags include BUILTIN_TAG = "server-management" via the safe-union pattern.
- Tool description carries the semantic clauses for Code Mode discovery.
- ENABLE_REPORT_FIELDS_TOOL=false hides the tool; list_report_fields still works.
- _report_fields_debug is hidden unless AMAZON_ADS_DEBUG_TOOLS=true.
"""

from __future__ import annotations

import pytest
from fastmcp import FastMCP

from amazon_ads_mcp.server.builtin_tools import register_report_catalog_tools


def _tool_names(server: FastMCP) -> set[str]:
    # FastMCP 3.x exposes a list of ToolInfo dicts via list_tools (or sync
    # equivalent). Fall back to the registered tool manager if present.
    manager = getattr(server, "_tool_manager", None) or getattr(server, "_tools", None)
    if manager is not None and hasattr(manager, "_tools"):
        return set(manager._tools.keys())
    # Best-effort fallback: walk known FastMCP internals.
    return {t.name for t in getattr(server, "tools", [])}


@pytest.mark.asyncio
async def test_report_fields_registered_by_default(monkeypatch):
    monkeypatch.delenv("ENABLE_REPORT_FIELDS_TOOL", raising=False)
    server = FastMCP("test")
    await register_report_catalog_tools(server)

    tools = await server.list_tools()
    names = {getattr(t, "name", None) for t in tools}
    assert "list_report_fields" in names
    assert "report_fields" in names


@pytest.mark.asyncio
async def test_env_flag_disables_report_fields_but_keeps_baseline(monkeypatch):
    """ENABLE_REPORT_FIELDS_TOOL=false hides the new tool; baseline stays."""
    # Reset settings cache so the env flag is picked up on rebuild.
    monkeypatch.setenv("ENABLE_REPORT_FIELDS_TOOL", "false")

    # Rebuild settings instance so the flag takes effect in this test.
    from amazon_ads_mcp.config import settings as settings_mod

    # Rebuild the singleton so the monkeypatched env var takes effect.
    settings_mod.settings = settings_mod.Settings()
    # Also rebind the import in builtin_tools which captured the singleton
    # by name at import time.
    from amazon_ads_mcp.server import builtin_tools as _bt_mod

    _bt_mod.settings = settings_mod.settings

    server = FastMCP("test")
    await register_report_catalog_tools(server)

    tools = await server.list_tools()
    names = {getattr(t, "name", None) for t in tools}
    assert "list_report_fields" in names, "baseline must always register"
    assert "report_fields" not in names, "gated tool must be hidden"


@pytest.mark.asyncio
async def test_report_fields_description_carries_semantic_clauses(monkeypatch):
    monkeypatch.delenv("ENABLE_REPORT_FIELDS_TOOL", raising=False)

    from amazon_ads_mcp.config import settings as settings_mod

    # Rebuild the singleton so the monkeypatched env var takes effect.
    settings_mod.settings = settings_mod.Settings()
    # Also rebind the import in builtin_tools which captured the singleton
    # by name at import time.
    from amazon_ads_mcp.server import builtin_tools as _bt_mod

    _bt_mod.settings = settings_mod.settings

    server = FastMCP("test")
    await register_report_catalog_tools(server)

    tools = await server.list_tools()
    rf = next(t for t in tools if getattr(t, "name", None) == "report_fields")
    desc = (getattr(rf, "description", "") or "").lower()

    # Clause checklist (locked — not a full-string snapshot):
    for clause in ("mode", "query", "validate", "v1 catalog"):
        assert clause in desc, f"report_fields description missing clause: {clause!r}"
    # Must reference list_report_fields as the baseline tool.
    assert "list_report_fields" in desc


@pytest.mark.asyncio
async def test_report_fields_debug_hidden_by_default(monkeypatch):
    monkeypatch.delenv("AMAZON_ADS_DEBUG_TOOLS", raising=False)
    monkeypatch.delenv("ENABLE_REPORT_FIELDS_TOOL", raising=False)

    from amazon_ads_mcp.config import settings as settings_mod

    # Rebuild the singleton so the monkeypatched env var takes effect.
    settings_mod.settings = settings_mod.Settings()
    # Also rebind the import in builtin_tools which captured the singleton
    # by name at import time.
    from amazon_ads_mcp.server import builtin_tools as _bt_mod

    _bt_mod.settings = settings_mod.settings

    server = FastMCP("test")
    await register_report_catalog_tools(server)

    tools = await server.list_tools()
    names = {getattr(t, "name", None) for t in tools}
    assert "_report_fields_debug" not in names


@pytest.mark.asyncio
async def test_report_fields_debug_exposed_when_env_flag_set(monkeypatch):
    monkeypatch.setenv("AMAZON_ADS_DEBUG_TOOLS", "true")
    monkeypatch.delenv("ENABLE_REPORT_FIELDS_TOOL", raising=False)

    from amazon_ads_mcp.config import settings as settings_mod

    # Rebuild the singleton so the monkeypatched env var takes effect.
    settings_mod.settings = settings_mod.Settings()
    # Also rebind the import in builtin_tools which captured the singleton
    # by name at import time.
    from amazon_ads_mcp.server import builtin_tools as _bt_mod

    _bt_mod.settings = settings_mod.settings

    server = FastMCP("test")
    await register_report_catalog_tools(server)

    tools = await server.list_tools()
    names = {getattr(t, "name", None) for t in tools}
    assert "_report_fields_debug" in names
