"""§8.3 "Attribution": the Code Mode sandbox bridge
(`server/code_mode.py`'s `bridged_call_tool`) sets tool_name too --
unit-tested here with a stub sandbox call, per the brief. This is the
design §7.1 attribution gap: `bridged_call_tool` dispatches
`original_call_tool` WITHOUT going through `ServerBuilder`'s middleware
chain (so `ToolAttributionMiddleware`, tested in `test_attribution.py`,
never runs for it) -- `code_mode.py` sets the SAME ContextVar directly
instead.

Not skipif-guarded: exercises `amazon_ads_mcp.server.code_mode` and
`amazon_ads_mcp.metering.attribution`, neither of which depends on
`mcp_outbound_metering` -- same rationale as `test_attribution.py`.
"""

from __future__ import annotations

import asyncio
from unittest.mock import patch

import pytest

from amazon_ads_mcp.auth.session_state import reset_all_session_state
from amazon_ads_mcp.metering.attribution import get_tool_name
from amazon_ads_mcp.server.code_mode import create_auth_bridging_sandbox_provider


class _DummyContext:
    """Minimal FastMCP-context double satisfying
    `middleware.auth_session_bridge.has_auth_session` (needs `get_state`
    and a non-None `request_context`) -- same shape as
    `tests/unit/test_code_mode.py`'s own `DummyContext`."""

    def __init__(self) -> None:
        self.request_context = object()
        self.state: dict = {}

    async def get_state(self, key):
        return self.state.get(key)

    async def set_state(self, key, value):
        self.state[key] = value


class _StubSandbox:
    """A stub sandbox: `.run()` just calls `external_functions["call_tool"]`
    directly (whatever `AuthBridgingSandboxProvider.run` installed --
    `bridged_call_tool` when a parent context is present, the original
    otherwise) and returns whatever it returns."""

    def __init__(self) -> None:
        self.observed_tool_names: list = []

    async def run(self, code, *, inputs=None, external_functions=None):
        call_tool = external_functions["call_tool"]
        result = await call_tool("search_profiles", {"query": "acme"})
        self.observed_tool_names.append(get_tool_name())
        return result


@pytest.fixture(autouse=True)
def _reset_state():
    reset_all_session_state()
    yield
    reset_all_session_state()


def test_bridged_call_tool_sets_tool_name_during_nested_dispatch() -> None:
    observed_during_call = {}

    async def fake_call_tool(name, params):
        observed_during_call["tool_name"] = get_tool_name()
        observed_during_call["name_arg"] = name
        return {"ok": True}

    sandbox = _StubSandbox()
    provider = create_auth_bridging_sandbox_provider(sandbox)
    ctx = _DummyContext()

    async def scenario():
        with patch("amazon_ads_mcp.server.code_mode.get_context", return_value=ctx):
            return await provider.run(
                "print('noop')",
                inputs={},
                external_functions={"call_tool": fake_call_tool},
            )

    result = asyncio.run(scenario())
    assert result == {"ok": True}
    # tool_name was set to the CALLED tool's name during the nested
    # dispatch -- attributed to "search_profiles", not e.g. a code-mode
    # meta-tool name.
    assert observed_during_call["tool_name"] == "search_profiles"
    assert observed_during_call["name_arg"] == "search_profiles"
    # And reset afterward -- outside the bridge, nothing leaks.
    assert get_tool_name() is None


def test_bridged_call_tool_resets_tool_name_even_when_call_tool_raises() -> None:
    async def failing_call_tool(name, params):
        assert get_tool_name() == "search_profiles"
        raise RuntimeError("boom")

    sandbox_calls = {}

    class _RaisingSandbox:
        async def run(self, code, *, inputs=None, external_functions=None):
            call_tool = external_functions["call_tool"]
            try:
                await call_tool("search_profiles", {})
            except RuntimeError as exc:
                sandbox_calls["caught"] = str(exc)
            return None

    provider = create_auth_bridging_sandbox_provider(_RaisingSandbox())
    ctx = _DummyContext()

    async def scenario():
        with patch("amazon_ads_mcp.server.code_mode.get_context", return_value=ctx):
            return await provider.run(
                "print('noop')",
                inputs={},
                external_functions={"call_tool": failing_call_tool},
            )

    asyncio.run(scenario())
    assert "caught" in sandbox_calls
    assert get_tool_name() is None


def test_without_parent_context_original_call_tool_is_used_unwrapped() -> None:
    """No parent MCP context (get_context() raises, matching startup/
    introspection paths per has_auth_session's own docstring) -> the
    bridge never installs bridged_call_tool at all, so tool_name is never
    set (missing attribution -- must not crash, per ruling #5)."""
    observed = {}

    async def fake_call_tool(name, params):
        observed["tool_name"] = get_tool_name()
        return {"ok": True}

    class _PassthroughSandbox:
        async def run(self, code, *, inputs=None, external_functions=None):
            return await external_functions["call_tool"]("search_profiles", {})

    provider = create_auth_bridging_sandbox_provider(_PassthroughSandbox())

    async def scenario():
        with patch(
            "amazon_ads_mcp.server.code_mode.get_context",
            side_effect=RuntimeError("no context"),
        ):
            return await provider.run(
                "print('noop')",
                inputs={},
                external_functions={"call_tool": fake_call_tool},
            )

    result = asyncio.run(scenario())
    assert result == {"ok": True}
    assert observed["tool_name"] is None
