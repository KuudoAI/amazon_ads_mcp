"""Tests for tool-group enable/disable + dynamic tool registration.

Why this file exists: tool-group lifecycle is a known regression magnet
(documented in the round-19 prioritization). The interesting properties
are not "do the tools exist" but:

1. ``list_tool_groups`` reports stable per-group counts even when some
   groups are disabled (``group_tool_counts`` is the snapshot taken at
   mount time, before disable).
2. ``enable_tool_group`` flips visibility on all sub-servers under a
   prefix — including the case where multiple specs share one prefix
   (``mounted_servers[prefix]`` is ``List[FastMCP]``, not a single one).
3. The disable path lists tools BEFORE disabling, so it can report what
   it just hid; the enable path enables BEFORE listing, so it can report
   what just became visible. Order matters.
4. Unknown-prefix calls return a structured error envelope, not a raise.
5. Re-enabling an already-enabled group is idempotent (no double
   counting, no error).

The tests build minimal sub-server FastMCP instances directly rather
than going through the full ``ServerBuilder`` mount pipeline — keeps
the test focused on the lifecycle contract.
"""

from __future__ import annotations

import pytest
from fastmcp import FastMCP

from amazon_ads_mcp.models.builtin_responses import (
    EnableToolGroupResponse,
    ToolGroupInfo,
    ToolGroupsResponse,
)
from amazon_ads_mcp.server.builtin_tools import register_tool_group_tools


# --- Helpers --------------------------------------------------------------


async def _make_sub_server_with_n_tools(name: str, n: int) -> FastMCP:
    """Build a child FastMCP with ``n`` no-op tools.

    Tools are registered as enabled by default; tests explicitly disable
    them when simulating "group not yet activated" state.
    """
    sub = FastMCP(name)
    for i in range(n):
        # Distinct closures so the tool name and async fn don't collide
        async def _fn(_i: int = i) -> int:
            return _i

        sub.tool(name=f"tool_{i}")(_fn)
    return sub


async def _build_parent_with_groups(
    groups: dict[str, list[FastMCP]],
    counts: dict[str, int] | None = None,
) -> FastMCP:
    """Build a parent FastMCP with the tool-group tools registered."""
    parent = FastMCP("test-parent")
    await register_tool_group_tools(parent, groups, counts)
    return parent


async def _call_list_tool_groups(parent: FastMCP) -> ToolGroupsResponse:
    """Invoke list_tool_groups via the in-memory MCP client."""
    from fastmcp import Client

    async with Client(parent) as client:
        result = await client.call_tool("list_tool_groups", {})
    # FastMCP's structured-output returns a dict that maps to the model.
    return ToolGroupsResponse.model_validate(result.structured_content)


async def _call_enable(
    parent: FastMCP, prefix: str, enable: bool = True
) -> EnableToolGroupResponse:
    from fastmcp import Client

    async with Client(parent) as client:
        result = await client.call_tool(
            "enable_tool_group", {"prefix": prefix, "enable": enable}
        )
    return EnableToolGroupResponse.model_validate(result.structured_content)


# --- list_tool_groups -----------------------------------------------------


class TestListToolGroups:
    @pytest.mark.asyncio
    async def test_empty_mounted_servers_returns_zero_groups(self) -> None:
        parent = await _build_parent_with_groups({})
        resp = await _call_list_tool_groups(parent)
        assert resp.success is True
        assert resp.groups == []
        assert resp.total_tools == 0
        assert resp.enabled_tools == 0

    @pytest.mark.asyncio
    async def test_reports_pre_stored_counts_even_when_disabled(self) -> None:
        """Critical property: ``group_tool_counts`` is a snapshot from
        mount time. After disable, ``list_tools()`` returns 0 — but the
        reported total must be the pre-stored count, not 0. This is what
        lets clients see what they *could* enable."""
        sub = await _make_sub_server_with_n_tools("cm-sub", n=3)
        # Disable the group — simulating the "default-off" startup state
        sub.disable(components={"tool"})
        parent = await _build_parent_with_groups({"cm": [sub]}, counts={"cm": 3})

        resp = await _call_list_tool_groups(parent)
        assert len(resp.groups) == 1
        cm = resp.groups[0]
        assert cm.prefix == "cm"
        assert cm.tool_count == 3  # pre-stored — ignores current disabled state
        assert cm.enabled is False
        assert resp.total_tools == 3
        assert resp.enabled_tools == 0  # nothing actually visible

    @pytest.mark.asyncio
    async def test_reports_active_count_when_enabled(self) -> None:
        sub = await _make_sub_server_with_n_tools("cm-sub", n=2)
        # Enabled at startup
        parent = await _build_parent_with_groups({"cm": [sub]}, counts={"cm": 2})

        resp = await _call_list_tool_groups(parent)
        cm = resp.groups[0]
        assert cm.enabled is True
        assert cm.tool_count == 2
        assert resp.enabled_tools == 2

    @pytest.mark.asyncio
    async def test_multiple_specs_under_one_prefix_summed(self) -> None:
        """``mounted_servers[prefix]`` is ``List[FastMCP]``: AMC mounts
        4 specs under ``amc``. Counts must aggregate across the list."""
        a = await _make_sub_server_with_n_tools("amc-a", n=2)
        b = await _make_sub_server_with_n_tools("amc-b", n=3)
        parent = await _build_parent_with_groups(
            {"amc": [a, b]}, counts={"amc": 5}
        )

        resp = await _call_list_tool_groups(parent)
        amc = resp.groups[0]
        assert amc.tool_count == 5  # combined snapshot
        assert resp.enabled_tools == 5

    @pytest.mark.asyncio
    async def test_multiple_groups_listed(self) -> None:
        cm = await _make_sub_server_with_n_tools("cm", n=2)
        dsp = await _make_sub_server_with_n_tools("dsp", n=3)
        parent = await _build_parent_with_groups(
            {"cm": [cm], "dsp": [dsp]}, counts={"cm": 2, "dsp": 3}
        )

        resp = await _call_list_tool_groups(parent)
        prefixes = {g.prefix for g in resp.groups}
        assert prefixes == {"cm", "dsp"}
        assert resp.total_tools == 5

    @pytest.mark.asyncio
    async def test_falls_back_to_active_count_when_no_prestore(self) -> None:
        """If a group was mounted without a pre-stored count, the function
        falls back to the live ``list_tools()`` count. Documents the
        fallback path so a missing entry in ``group_tool_counts`` doesn't
        silently report zero tools."""
        sub = await _make_sub_server_with_n_tools("x", n=4)
        parent = await _build_parent_with_groups({"x": [sub]}, counts=None)

        resp = await _call_list_tool_groups(parent)
        x = resp.groups[0]
        assert x.tool_count == 4

    @pytest.mark.asyncio
    async def test_message_mentions_enable_call(self) -> None:
        sub = await _make_sub_server_with_n_tools("cm", n=1)
        sub.disable(components={"tool"})
        parent = await _build_parent_with_groups({"cm": [sub]}, counts={"cm": 1})

        resp = await _call_list_tool_groups(parent)
        # Sanity: agents read this message; "enable_tool_group" must appear.
        assert "enable_tool_group" in resp.message


# --- enable_tool_group ----------------------------------------------------


class TestEnableToolGroup:
    @pytest.mark.asyncio
    async def test_enable_returns_tool_count_and_names(self) -> None:
        sub = await _make_sub_server_with_n_tools("cm", n=3)
        sub.disable(components={"tool"})
        parent = await _build_parent_with_groups({"cm": [sub]}, counts={"cm": 3})

        resp = await _call_enable(parent, "cm", enable=True)
        assert resp.success is True
        assert resp.prefix == "cm"
        assert resp.enabled is True
        assert resp.tool_count == 3
        # Tool names use prefix_toolname format (per registration code)
        assert all(name.startswith("cm_") for name in resp.tool_names)
        assert sorted(resp.tool_names) == resp.tool_names  # sorted by impl

    @pytest.mark.asyncio
    async def test_disable_returns_tool_count_and_names(self) -> None:
        """Disable must list tools BEFORE disabling so it can report what
        it just hid. If the impl ever flips that order, this test fails."""
        sub = await _make_sub_server_with_n_tools("cm", n=2)
        parent = await _build_parent_with_groups({"cm": [sub]}, counts={"cm": 2})

        resp = await _call_enable(parent, "cm", enable=False)
        assert resp.success is True
        assert resp.enabled is False
        assert resp.tool_count == 2  # would be 0 if list ran after disable
        assert len(resp.tool_names) == 2

    @pytest.mark.asyncio
    async def test_unknown_prefix_returns_structured_error(self) -> None:
        sub = await _make_sub_server_with_n_tools("cm", n=1)
        parent = await _build_parent_with_groups({"cm": [sub]}, counts={"cm": 1})

        resp = await _call_enable(parent, "no-such-group", enable=True)
        assert resp.success is False
        assert resp.prefix == "no-such-group"
        assert resp.error is not None
        # Error message must list available groups so the agent can recover
        assert "cm" in resp.error

    @pytest.mark.asyncio
    async def test_enable_then_list_shows_enabled(self) -> None:
        """Round-trip: enable a disabled group, then verify list reports
        it enabled. Catches state-machine drift between the two tools."""
        sub = await _make_sub_server_with_n_tools("cm", n=2)
        sub.disable(components={"tool"})
        parent = await _build_parent_with_groups({"cm": [sub]}, counts={"cm": 2})

        # Initially disabled
        resp1 = await _call_list_tool_groups(parent)
        assert resp1.groups[0].enabled is False
        assert resp1.enabled_tools == 0

        # Enable
        await _call_enable(parent, "cm", enable=True)

        # Now reports enabled
        resp2 = await _call_list_tool_groups(parent)
        assert resp2.groups[0].enabled is True
        assert resp2.enabled_tools == 2

    @pytest.mark.asyncio
    async def test_disable_then_list_shows_disabled(self) -> None:
        """Inverse round-trip."""
        sub = await _make_sub_server_with_n_tools("cm", n=2)
        parent = await _build_parent_with_groups({"cm": [sub]}, counts={"cm": 2})

        resp1 = await _call_list_tool_groups(parent)
        assert resp1.groups[0].enabled is True

        await _call_enable(parent, "cm", enable=False)

        resp2 = await _call_list_tool_groups(parent)
        assert resp2.groups[0].enabled is False
        assert resp2.enabled_tools == 0

    @pytest.mark.asyncio
    async def test_re_enable_already_enabled_is_idempotent(self) -> None:
        """Idempotence: calling enable on an already-enabled group must
        not double-count or fail."""
        sub = await _make_sub_server_with_n_tools("cm", n=2)
        parent = await _build_parent_with_groups({"cm": [sub]}, counts={"cm": 2})

        resp1 = await _call_enable(parent, "cm", enable=True)
        resp2 = await _call_enable(parent, "cm", enable=True)
        assert resp1.tool_count == resp2.tool_count == 2
        assert resp1.success and resp2.success

    @pytest.mark.asyncio
    async def test_enable_aggregates_across_multi_spec_prefix(self) -> None:
        """When two FastMCPs share a prefix (e.g. amc), enable_tool_group
        must enable BOTH and report combined counts."""
        a = await _make_sub_server_with_n_tools("amc-a", n=2)
        b = await _make_sub_server_with_n_tools("amc-b", n=3)
        a.disable(components={"tool"})
        b.disable(components={"tool"})
        parent = await _build_parent_with_groups(
            {"amc": [a, b]}, counts={"amc": 5}
        )

        resp = await _call_enable(parent, "amc", enable=True)
        assert resp.tool_count == 5
        assert len(resp.tool_names) == 5

    @pytest.mark.asyncio
    async def test_disable_aggregates_across_multi_spec_prefix(self) -> None:
        a = await _make_sub_server_with_n_tools("amc-a", n=2)
        b = await _make_sub_server_with_n_tools("amc-b", n=3)
        parent = await _build_parent_with_groups(
            {"amc": [a, b]}, counts={"amc": 5}
        )

        resp = await _call_enable(parent, "amc", enable=False)
        assert resp.tool_count == 5
        assert resp.enabled is False

    @pytest.mark.asyncio
    async def test_unknown_prefix_does_not_modify_other_groups(self) -> None:
        """Failing on unknown prefix must not have side effects on other
        groups (defensive)."""
        cm = await _make_sub_server_with_n_tools("cm", n=2)
        parent = await _build_parent_with_groups({"cm": [cm]}, counts={"cm": 2})

        await _call_enable(parent, "ghost", enable=True)

        # cm still has its pre-existing state
        resp = await _call_list_tool_groups(parent)
        assert resp.groups[0].enabled is True
        assert resp.enabled_tools == 2


# --- ServerBuilder integration: mounted_servers + group_tool_counts ----


class TestServerBuilderTracking:
    """The ServerBuilder is what populates ``mounted_servers`` and
    ``group_tool_counts``. These tests don't require a full mount pipeline;
    they verify the *shape* of those structures via direct construction."""

    def test_mounted_servers_default_is_empty(self) -> None:
        """ServerBuilder starts with empty mount tracking — coverage of
        the ``__init__`` paths."""
        from amazon_ads_mcp.server.server_builder import ServerBuilder

        builder = ServerBuilder()
        assert builder.mounted_servers == {}
        assert builder.group_tool_counts == {}

    def test_mounted_servers_dict_is_list_per_prefix(self) -> None:
        """Multiple specs under one prefix share a list — locks in the
        shape that AMC depends on (4 specs → 1 prefix → list[FastMCP])."""
        from amazon_ads_mcp.server.server_builder import ServerBuilder

        builder = ServerBuilder()
        builder.mounted_servers.setdefault("amc", []).append(
            FastMCP("amc-a")
        )
        builder.mounted_servers.setdefault("amc", []).append(
            FastMCP("amc-b")
        )
        assert len(builder.mounted_servers["amc"]) == 2
