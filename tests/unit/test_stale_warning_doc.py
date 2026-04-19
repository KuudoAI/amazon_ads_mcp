"""Pins Issue 14 (bug_fix_plan.md §5) — stale_warning works and is documented.

stale_warning is populated when the catalog parsed_at exceeds the
LIST_REPORT_FIELDS_STALE_DAYS threshold (default 90). Setting the env
var to 0 must trigger the warning on every response for a past catalog.
Tool description must mention the env var so agents can self-serve.
"""

from __future__ import annotations

import pytest
from fastmcp import FastMCP

from amazon_ads_mcp.server.builtin_tools import register_report_catalog_tools
from amazon_ads_mcp.tools.report_fields_v1_handler import handle


@pytest.mark.asyncio
async def test_tool_description_mentions_stale_warning_env_var(monkeypatch):
    monkeypatch.delenv("ENABLE_REPORT_FIELDS_TOOL", raising=False)
    from amazon_ads_mcp.config import settings as settings_mod
    from amazon_ads_mcp.server import builtin_tools as _bt_mod

    settings_mod.settings = settings_mod.Settings()
    _bt_mod.settings = settings_mod.settings

    server = FastMCP("test")
    await register_report_catalog_tools(server)

    tools = await server.list_tools()
    rf = next(t for t in tools if getattr(t, "name", None) == "report_fields")
    desc = (getattr(rf, "description", "") or "").lower()

    # Pinned clause — must reference stale_warning AND the env var name.
    assert "stale_warning" in desc
    assert "list_report_fields_stale_days" in desc


def test_stale_warning_populates_when_days_env_is_zero(monkeypatch):
    """With threshold 0, every response carries stale_warning (catalog parsed
    before 'now' is trivially > 0 days old)."""
    monkeypatch.setenv("LIST_REPORT_FIELDS_STALE_DAYS", "0")

    r = handle(mode="query", category="metric", limit=1)
    # The shipped catalog's parsed_at is in the past; 0-day threshold
    # guarantees a non-None warning.
    assert r.stale_warning is not None
    assert "old" in r.stale_warning.lower()
