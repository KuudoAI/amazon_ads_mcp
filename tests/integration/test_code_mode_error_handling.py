"""Integration tests for catchable call_tool errors in code-mode execute.

These exercise the real Monty sandbox path so the exception marshaling
boundary is covered end-to-end. The behavior under test was added because
raw ToolError / NotFoundError types from ``ctx.fastmcp.call_tool`` do not
reify reliably inside the Monty interpreter and the script aborts before
any in-sandbox ``try/except`` can catch them.

The fix in :mod:`amazon_ads_mcp.server.code_mode` re-raises every
``call_tool`` failure as a builtin ``RuntimeError(f"<OriginalType>: <msg>")``
which Monty marshals cleanly into the sandbox.
"""

from __future__ import annotations

import json

import pytest
import pytest_asyncio

pytest.importorskip("fastmcp")
pytest.importorskip("pydantic_monty")


def _extract_text_payload(call_result):
    assert call_result.content, "Expected call result content"
    content = call_result.content[0]
    return json.loads(content.text) if hasattr(content, "text") else content


@pytest_asyncio.fixture
async def code_mode_server():
    """FastMCP server with two real tools and the real Monty sandbox.

    ``echo`` succeeds and round-trips its payload. ``boom`` deliberately
    raises so the test can drive the failure path.
    """

    from fastmcp import FastMCP
    from fastmcp.experimental.transforms import code_mode as fm_code_mode

    from amazon_ads_mcp.server.code_mode import (
        EXECUTE_DESCRIPTION,
        MontyDispatchSandboxProvider,
        create_auth_bridging_sandbox_provider,
    )

    server = FastMCP(name="code-mode-error-handling-test")

    @server.tool
    async def echo(value: str) -> dict:
        return {"value": value}

    @server.tool
    async def boom(reason: str = "boom") -> dict:
        raise ValueError(reason)

    sandbox = MontyDispatchSandboxProvider(
        limits={"max_duration_secs": 5.0, "max_memory": 50_000_000}
    )
    transform = fm_code_mode.CodeMode(
        sandbox_provider=create_auth_bridging_sandbox_provider(sandbox),
        discovery_tools=[],
        execute_description=EXECUTE_DESCRIPTION,
    )
    server.add_transform(transform)
    return server


@pytest.mark.asyncio
async def test_unknown_tool_is_catchable_as_runtime_error(code_mode_server):
    """Calling an unknown tool inside ``try/except RuntimeError`` is caught.

    Before the fix: the script aborted with MontyRuntimeError → ToolError.
    After the fix: the script catches and returns a structured payload.
    """
    from fastmcp import Client

    code = (
        "import json\n"
        "try:\n"
        "    await call_tool('no_such_tool', {})\n"
        "    return json.dumps({'caught': False})\n"
        "except RuntimeError as exc:\n"
        "    return json.dumps({'caught': True, 'message': str(exc)})\n"
    )

    async with Client(code_mode_server) as client:
        result = await client.call_tool("execute", {"code": code})

    payload = _extract_text_payload(result)
    assert payload["caught"] is True
    # Original error type name is preserved so callers can pattern-match on it.
    assert "no_such_tool" in payload["message"]


@pytest.mark.asyncio
async def test_failing_tool_does_not_abort_subsequent_calls(code_mode_server):
    """A mid-script failure inside ``try/except`` lets later calls still run.

    This is the "test multiple variants in one block" use case: the LLM
    needs to recover from a single bad call without paying N round trips.
    """
    from fastmcp import Client

    code = (
        "import json\n"
        "steps = []\n"
        "first = await call_tool('echo', {'value': 'one'})\n"
        "steps.append(first['value'])\n"
        "try:\n"
        "    await call_tool('boom', {'reason': 'expected'})\n"
        "    steps.append('boom-unexpectedly-succeeded')\n"
        "except RuntimeError as exc:\n"
        "    steps.append('caught')\n"
        "third = await call_tool('echo', {'value': 'three'})\n"
        "steps.append(third['value'])\n"
        "return json.dumps({'steps': steps})\n"
    )

    async with Client(code_mode_server) as client:
        result = await client.call_tool("execute", {"code": code})

    payload = _extract_text_payload(result)
    assert payload["steps"] == ["one", "caught", "three"]


@pytest.mark.asyncio
async def test_probe_many_candidates_in_one_block(code_mode_server):
    """Probing a list of candidate tool names in one block returns the first
    that succeeds. Asserts behavior, not round-trip count.
    """
    from fastmcp import Client

    candidates = ["bogus_a", "bogus_b", "bogus_c", "bogus_d", "echo"]
    code = (
        "import json\n"
        f"candidates = {candidates!r}\n"
        "attempts = []\n"
        "first_success = None\n"
        "for name in candidates:\n"
        "    try:\n"
        "        await call_tool(name, {'value': name})\n"
        "        attempts.append({'name': name, 'ok': True})\n"
        "        first_success = name\n"
        "        break\n"
        "    except RuntimeError:\n"
        "        attempts.append({'name': name, 'ok': False})\n"
        "return json.dumps({'first_success': first_success, 'attempts': attempts})\n"
    )

    async with Client(code_mode_server) as client:
        result = await client.call_tool("execute", {"code": code})

    payload = _extract_text_payload(result)
    assert payload["first_success"] == "echo"
    assert [a["name"] for a in payload["attempts"]] == candidates
    assert [a["ok"] for a in payload["attempts"]] == [False, False, False, False, True]
