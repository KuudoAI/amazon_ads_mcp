"""Unit tests for progressive tool disclosure."""


import pytest
from fastmcp import Client, FastMCP


@pytest.mark.asyncio
async def test_disable_mounted_tools_hides_from_client():
    """Disabling tools on a child server hides them from parent client."""
    parent = FastMCP("parent")
    child = FastMCP("child")

    @child.tool()
    def child_tool() -> str:
        """A child tool."""
        return "hello"

    @parent.tool()
    def parent_tool() -> str:
        """A parent tool."""
        return "world"

    parent.mount(child, namespace="ch")

    # Disable child tools (v3: server-level disable)
    child.disable(components={"tool"})

    # Client should only see parent_tool
    async with Client(parent) as client:
        visible = await client.list_tools()
        names = [t.name for t in visible]
        assert "parent_tool" in names
        assert "ch_child_tool" not in names


@pytest.mark.asyncio
async def test_enable_restores_tools():
    """Re-enabling tools on a child server makes them visible again."""
    parent = FastMCP("parent")
    child = FastMCP("child")

    @child.tool()
    def child_tool() -> str:
        """A child tool."""
        return "hello"

    @parent.tool()
    def parent_tool() -> str:
        """A parent tool."""
        return "world"

    parent.mount(child, namespace="ch")

    # Disable then re-enable (v3: server-level operations)
    child.disable(components={"tool"})
    child.enable(components={"tool"})

    # Client should see both tools
    async with Client(parent) as client:
        visible = await client.list_tools()
        names = [t.name for t in visible]
        assert "parent_tool" in names
        assert "ch_child_tool" in names


@pytest.mark.asyncio
async def test_progressive_disclosure_env_flag_default(monkeypatch):
    """Progressive disclosure is disabled by default (Claude Desktop compat)."""
    from types import SimpleNamespace

    monkeypatch.setattr(
        "amazon_ads_mcp.server.server_builder.get_auth_manager",
        lambda: SimpleNamespace(provider=None),
    )
    monkeypatch.delenv("PROGRESSIVE_TOOL_DISCLOSURE", raising=False)

    from amazon_ads_mcp.server.server_builder import ServerBuilder

    builder = ServerBuilder()
    assert builder._progressive_disclosure_enabled() is False


@pytest.mark.asyncio
async def test_progressive_disclosure_env_flag_enabled(monkeypatch):
    """Progressive disclosure can be enabled via env flag."""
    from types import SimpleNamespace

    monkeypatch.setattr(
        "amazon_ads_mcp.server.server_builder.get_auth_manager",
        lambda: SimpleNamespace(provider=None),
    )
    monkeypatch.setenv("PROGRESSIVE_TOOL_DISCLOSURE", "true")

    from amazon_ads_mcp.server.server_builder import ServerBuilder

    builder = ServerBuilder()
    assert builder._progressive_disclosure_enabled() is True


@pytest.mark.asyncio
async def test_progressive_disclosure_env_flag_disabled(monkeypatch):
    """Progressive disclosure can be disabled via env flag."""
    from types import SimpleNamespace

    monkeypatch.setattr(
        "amazon_ads_mcp.server.server_builder.get_auth_manager",
        lambda: SimpleNamespace(provider=None),
    )
    monkeypatch.setenv("PROGRESSIVE_TOOL_DISCLOSURE", "false")

    from amazon_ads_mcp.server.server_builder import ServerBuilder

    builder = ServerBuilder()
    assert builder._progressive_disclosure_enabled() is False


@pytest.mark.asyncio
async def test_tool_group_list_and_enable():
    """Integration test: list_tool_groups and enable_tool_group work together."""
    from amazon_ads_mcp.server.builtin_tools import register_tool_group_tools

    parent = FastMCP("parent")
    child_a = FastMCP("child_a")
    child_b = FastMCP("child_b")

    @child_a.tool()
    def tool_a1() -> str:
        """Tool A1."""
        return "a1"

    @child_a.tool()
    def tool_a2() -> str:
        """Tool A2."""
        return "a2"

    @child_b.tool()
    def tool_b1() -> str:
        """Tool B1."""
        return "b1"

    parent.mount(child_a, namespace="ga")
    parent.mount(child_b, namespace="gb")

    mounted = {"ga": [child_a], "gb": [child_b]}

    # Count tools before disabling (for total counts)
    group_tool_counts: dict[str, int] = {}
    for prefix, sub_servers in mounted.items():
        count = 0
        for sub in sub_servers:
            tools = await sub.list_tools()
            count += len(tools)
        group_tool_counts[prefix] = count

    # Disable all (v3: server-level disable)
    for sub_servers in mounted.values():
        for sub in sub_servers:
            sub.disable(components={"tool"})

    # Register tool group tools
    await register_tool_group_tools(
        parent, mounted, group_tool_counts=group_tool_counts
    )

    # Verify only builtin tools visible
    async with Client(parent) as client:
        visible = await client.list_tools()
        names = [t.name for t in visible]
        assert "list_tool_groups" in names
        assert "enable_tool_group" in names
        assert "ga_tool_a1" not in names
        assert "gb_tool_b1" not in names

        # Call list_tool_groups
        import json

        result = await client.call_tool(
            "list_tool_groups", arguments={}
        )
        data = json.loads(result.content[0].text)
        assert data["success"] is True
        assert data["total_tools"] == 3
        assert data["enabled_tools"] == 0

        # Enable group ga
        result = await client.call_tool(
            "enable_tool_group", arguments={"prefix": "ga"}
        )
        data = json.loads(result.content[0].text)
        assert data["success"] is True
        assert data["tool_count"] == 2
        assert data["enabled"] is True
        assert sorted(data["tool_names"]) == ["ga_tool_a1", "ga_tool_a2"]

    # Now ga tools should be visible
    async with Client(parent) as client:
        visible = await client.list_tools()
        names = [t.name for t in visible]
        assert "ga_tool_a1" in names
        assert "ga_tool_a2" in names
        assert "gb_tool_b1" not in names  # Still disabled
