"""Unit tests for the tool_name attribution ContextVar + middleware (Task 22
ruling #5).

Not skipif-guarded: ``amazon_ads_mcp.metering.attribution`` has no
dependency on ``mcp_outbound_metering`` (only ``fastmcp``, already a core
dependency), so -- same rationale as ``test_compat_guard.py`` and
``test_normalizer.py`` -- it is tested on every supported Python version.
The §8.3 "middleware sets/resets tool_name" and "code_mode bridged path
sets it too" bullets are covered end-to-end (through the real
``AuthenticatedClient``/transport stack) in ``test_conformance.py`` and
``test_code_mode_attribution.py``; this module covers the primitive in
isolation.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from amazon_ads_mcp.metering.attribution import (
    ToolAttributionMiddleware,
    get_tool_name,
    tool_name_scope,
)


def test_no_scope_means_no_tool_name() -> None:
    assert get_tool_name() is None


def test_tool_name_scope_sets_and_resets() -> None:
    assert get_tool_name() is None
    with tool_name_scope("get_profiles"):
        assert get_tool_name() == "get_profiles"
    assert get_tool_name() is None


def test_tool_name_scope_resets_on_exception() -> None:
    with pytest.raises(RuntimeError):
        with tool_name_scope("boom_tool"):
            assert get_tool_name() == "boom_tool"
            raise RuntimeError("boom")
    assert get_tool_name() is None


def test_tool_name_scope_nests_and_restores_outer_value() -> None:
    with tool_name_scope("outer_tool"):
        assert get_tool_name() == "outer_tool"
        with tool_name_scope("inner_tool"):
            assert get_tool_name() == "inner_tool"
        assert get_tool_name() == "outer_tool"
    assert get_tool_name() is None


def _make_context(tool_name: str | None) -> SimpleNamespace:
    message = SimpleNamespace(name=tool_name) if tool_name is not None else None
    return SimpleNamespace(message=message)


@pytest.mark.parametrize("_unused", [1])
def test_middleware_sets_tool_name_during_call_next(_unused) -> None:
    import asyncio

    middleware = ToolAttributionMiddleware()
    observed = {}

    async def call_next(context):
        observed["tool_name"] = get_tool_name()
        return "ok"

    async def scenario():
        result = await middleware.on_call_tool(_make_context("search_profiles"), call_next)
        assert result == "ok"

    asyncio.run(scenario())
    assert observed["tool_name"] == "search_profiles"
    assert get_tool_name() is None  # reset after on_call_tool returns


def test_middleware_resets_even_when_call_next_raises() -> None:
    import asyncio

    middleware = ToolAttributionMiddleware()

    async def call_next(context):
        raise ValueError("downstream failure")

    async def scenario():
        with pytest.raises(ValueError):
            await middleware.on_call_tool(_make_context("page_profiles"), call_next)

    asyncio.run(scenario())
    assert get_tool_name() is None


def test_middleware_missing_message_name_is_none_not_a_crash() -> None:
    import asyncio

    middleware = ToolAttributionMiddleware()
    observed = {}

    async def call_next(context):
        observed["tool_name"] = get_tool_name()
        return "ok"

    async def scenario():
        await middleware.on_call_tool(_make_context(None), call_next)

    asyncio.run(scenario())
    assert observed["tool_name"] is None
