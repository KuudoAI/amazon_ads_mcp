"""Code Mode compatibility: report_fields must be tagged 'server-management'.

Locked contract (adsv1.md §4.8): all builtin tools including report_fields
must surface via Search / GetSchemas / GetTags with BUILTIN_TAG applied.
The existing `tag_builtin_tools` helper does this automatically after
registration; this test verifies the integration actually lands the tag
on our new tool.
"""

from __future__ import annotations

import pytest
from fastmcp import FastMCP

from amazon_ads_mcp.server.builtin_tools import register_report_catalog_tools
from amazon_ads_mcp.server.code_mode import BUILTIN_TAG, tag_builtin_tools


@pytest.mark.asyncio
async def test_report_fields_tagged_server_management(monkeypatch):
    monkeypatch.delenv("ENABLE_REPORT_FIELDS_TOOL", raising=False)
    from amazon_ads_mcp.config import settings as settings_mod

    settings_mod.settings = settings_mod.Settings()
    from amazon_ads_mcp.server import builtin_tools as _bt_mod

    _bt_mod.settings = settings_mod.settings

    server = FastMCP("test")
    await register_report_catalog_tools(server)
    n = await tag_builtin_tools(server)
    assert n > 0

    tool = await server.get_tool("report_fields")
    assert tool is not None
    assert BUILTIN_TAG in (tool.tags or set())


@pytest.mark.asyncio
async def test_list_report_fields_also_tagged_server_management(monkeypatch):
    """The baseline list_report_fields tool (unchanged) must also be tagged."""
    monkeypatch.delenv("ENABLE_REPORT_FIELDS_TOOL", raising=False)
    server = FastMCP("test")
    await register_report_catalog_tools(server)
    await tag_builtin_tools(server)

    tool = await server.get_tool("list_report_fields")
    assert tool is not None
    assert BUILTIN_TAG in (tool.tags or set())
