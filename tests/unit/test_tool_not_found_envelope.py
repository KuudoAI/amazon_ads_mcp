"""Phase 2 — tool-not-found envelope (SP-1 Ads parity).

Mirror of ``amazon_sp_mcp/tests/unit/test_tool_not_found_envelope.py``.
Both servers must classify ``fastmcp.exceptions.NotFoundError`` as
``error_kind=mcp_input_validation`` with ``error_code=TOOL_NOT_FOUND``.
"""

from __future__ import annotations

import json

import pytest
from fastmcp.exceptions import NotFoundError

from amazon_ads_mcp.middleware.error_envelope import build_envelope_from_exception


def _envelope(env: dict) -> dict:
    if isinstance(env, str):
        return json.loads(env)
    return env


def test_not_found_classifies_as_tool_not_found() -> None:
    """Round 12 SP-1 retag: NotFoundError now uses the dedicated
    ``tool_not_found`` error_kind, not ``mcp_input_validation``."""
    exc = NotFoundError("Unknown tool: 'list_ads_things'")
    env = _envelope(build_envelope_from_exception(exc, tool_name="list_ads_things"))
    assert env["error_kind"] == "tool_not_found"
    assert env["error_code"] == "TOOL_NOT_FOUND"
    assert env["retryable"] is False


def test_not_found_summary_does_not_blame_upstream() -> None:
    exc = NotFoundError("Unknown tool: 'list_ads_things'")
    env = _envelope(build_envelope_from_exception(exc, tool_name="list_ads_things"))
    summary = (env.get("summary") or "").lower()
    assert "ads api" not in summary, (
        "Tool-not-found never reaches upstream; summary must not "
        "blame the Ads API. Got: " + repr(env["summary"])
    )


def test_not_found_envelope_carries_tool_name() -> None:
    exc = NotFoundError("Unknown tool: 'list_ads_things'")
    env = _envelope(build_envelope_from_exception(exc, tool_name="list_ads_things"))
    in_tool = "list_ads_things" in (env.get("tool") or "")
    in_details = any(
        "list_ads_things" in (d.get("issue") or "") for d in (env.get("details") or [])
    )
    assert in_tool or in_details


def test_not_found_envelope_has_recovery_hint() -> None:
    exc = NotFoundError("Unknown tool: 'list_ads_things'")
    env = _envelope(build_envelope_from_exception(exc, tool_name="list_ads_things"))
    hints = env.get("hints") or []
    assert hints
    joined = " ".join(hints).lower()
    assert "tool" in joined or "name" in joined or "search" in joined


def test_not_found_envelope_has_v1_envelope_version() -> None:
    exc = NotFoundError("Unknown tool: 'list_ads_things'")
    env = _envelope(build_envelope_from_exception(exc, tool_name="list_ads_things"))
    assert env.get("_envelope_version") == 1


# Round 12 follow-up: extend envelope wrapping to prompts/resources paths.


def _envelope_from_tool_error(exc) -> dict:
    return json.loads(str(exc))


@pytest.mark.asyncio
async def test_envelope_middleware_wraps_get_prompt_not_found() -> None:
    """on_get_prompt must catch NotFoundError and emit a tool_not_found
    envelope just like on_call_tool, so prompt-name typos don't surface
    as bare JSON-RPC errors during client session warmup."""
    from fastmcp.exceptions import NotFoundError as _NF
    from fastmcp.exceptions import ToolError as _TE
    from amazon_ads_mcp.middleware.error_envelope_middleware import (
        ErrorEnvelopeMiddleware,
    )
    from unittest.mock import MagicMock

    mw = ErrorEnvelopeMiddleware()
    ctx = MagicMock()
    ctx.message = MagicMock(name="message")
    ctx.message.name = "missing_prompt"

    async def call_next(ctx):
        raise _NF("Unknown prompt: 'missing_prompt'")

    with pytest.raises(_TE) as exc_info:
        await mw.on_get_prompt(ctx, call_next)

    env = _envelope_from_tool_error(exc_info.value)
    assert env["error_kind"] == "tool_not_found"
    assert env["error_code"] == "TOOL_NOT_FOUND"


@pytest.mark.asyncio
async def test_envelope_middleware_wraps_read_resource_not_found() -> None:
    """on_read_resource must catch NotFoundError and emit a tool_not_found
    envelope, same pattern as on_get_prompt."""
    from fastmcp.exceptions import NotFoundError as _NF
    from fastmcp.exceptions import ToolError as _TE
    from amazon_ads_mcp.middleware.error_envelope_middleware import (
        ErrorEnvelopeMiddleware,
    )
    from unittest.mock import MagicMock

    mw = ErrorEnvelopeMiddleware()
    ctx = MagicMock()
    ctx.message = MagicMock(name="message")
    ctx.message.uri = "does://not/exist"
    ctx.message.name = None

    async def call_next(ctx):
        raise _NF("Unknown resource: 'does://not/exist'")

    with pytest.raises(_TE) as exc_info:
        await mw.on_read_resource(ctx, call_next)

    env = _envelope_from_tool_error(exc_info.value)
    assert env["error_kind"] == "tool_not_found"
    assert env["error_code"] == "TOOL_NOT_FOUND"


@pytest.mark.asyncio
async def test_envelope_middleware_get_prompt_passes_other_exceptions() -> None:
    """Non-NotFoundError exceptions on the prompt path must NOT be wrapped
    by the not-found envelope. They bubble normally."""
    from amazon_ads_mcp.middleware.error_envelope_middleware import (
        ErrorEnvelopeMiddleware,
    )
    from unittest.mock import MagicMock

    mw = ErrorEnvelopeMiddleware()
    ctx = MagicMock()
    ctx.message = MagicMock(name="message")
    ctx.message.name = "p"

    class _OtherErr(Exception):
        pass

    async def call_next(ctx):
        raise _OtherErr("something else")

    with pytest.raises(_OtherErr):
        await mw.on_get_prompt(ctx, call_next)
