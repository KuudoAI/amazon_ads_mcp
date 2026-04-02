"""Unit tests for tool naming utilities.

This module tests the tool naming functionality that ensures
tool names meet length and format requirements for MCP tools.
"""

import asyncio

from amazon_ads_mcp.utils.tool_naming import (
    MAX_TOOL_NAME,
    enforce_tool_name_limit,
    shorten_prefix,
    validate_tool_name,
)


class DummyTool:
    def __init__(self, name):
        self.name = name


class DummyServer:
    def __init__(self):
        self._tools = {"a" * 80: object(), "keep": object()}
        self._renamed = {}

    async def list_tools(self):
        return [DummyTool(name) for name in self._tools]

    def rename_tool(self, old, new):
        self._renamed[old] = new
        self._tools[new] = self._tools.pop(old)


def test_shorten_prefix_and_validate():
    assert shorten_prefix("AccountBudgets") in ("ab", "accoun")
    assert validate_tool_name("tool", prefix="ns")
    long = "x" * (MAX_TOOL_NAME + 1)
    assert not validate_tool_name(long)


def test_enforce_tool_name_limit_renames_long():
    srv = DummyServer()
    asyncio.run(enforce_tool_name_limit(srv, prefix="ns"))
    # The long name should be renamed
    assert any(len(k) < 80 for k in srv._tools.keys())
