"""Unit tests for R5 — wrap unknown-tool errors in v1 envelope JSON.

Defensive caller code patterns like:

    try:
        return await call_tool(name, params)
    except RuntimeError as e:
        env = json.loads(str(e))   # cross-server symmetry expectation
        handle(env)

were tripped by FastMCP's bare ``RuntimeError("NotFoundError: Unknown tool: …")``
for unknown-tool calls inside the Code Mode ``execute`` sandbox. R5 wraps
those in the same v1 envelope shape used for every other error kind, so
defensive code can rely on a single ``json.loads(str(e))`` path.
"""

from __future__ import annotations

import json


def test_translate_unknown_tool_returns_v1_envelope_runtime_error():
    """``NotFoundError`` from FastMCP gets translated into a RuntimeError
    whose message is parseable as a v1 envelope with
    ``error_kind: tool_not_found`` and ``error_code: TOOL_NOT_FOUND``."""
    from fastmcp.exceptions import NotFoundError

    from amazon_ads_mcp.server.code_mode import (
        translate_to_sandbox_runtime_error,
    )

    exc = NotFoundError("Unknown tool: totally_nonexistent_tool_xyz")
    result = translate_to_sandbox_runtime_error(exc)

    assert isinstance(result, RuntimeError)
    parsed = json.loads(str(result))
    assert parsed["_envelope_version"] == 1
    assert parsed["error_kind"] == "tool_not_found"
    assert parsed["error_code"] == "TOOL_NOT_FOUND"
    assert parsed["retryable"] is False
    assert "totally_nonexistent_tool_xyz" in parsed.get("summary", "")


def test_translate_unknown_tool_includes_helpful_hint():
    """The envelope should include a hint pointing the LLM at the
    discovery tools (``tool_search`` / ``list_tools``) so it can
    self-correct without a round-trip to the user."""
    from fastmcp.exceptions import NotFoundError

    from amazon_ads_mcp.server.code_mode import (
        translate_to_sandbox_runtime_error,
    )

    exc = NotFoundError("Unknown tool: xyz")
    result = translate_to_sandbox_runtime_error(exc)

    parsed = json.loads(str(result))
    hints = parsed.get("hints") or []
    assert any(
        "search" in h.lower() or "list_tools" in h.lower() or "discover" in h.lower()
        for h in hints
    ), f"expected discovery hint, got hints={hints}"


def test_translate_unknown_tool_extracts_tool_name():
    """When NotFoundError's message follows the ``Unknown tool: <name>``
    pattern, extract the name into the envelope's ``tool`` field so
    callers can branch on it programmatically."""
    from fastmcp.exceptions import NotFoundError

    from amazon_ads_mcp.server.code_mode import (
        translate_to_sandbox_runtime_error,
    )

    exc = NotFoundError("Unknown tool: my_specific_tool")
    result = translate_to_sandbox_runtime_error(exc)

    parsed = json.loads(str(result))
    assert parsed.get("tool") == "my_specific_tool"


def test_translate_other_exceptions_still_use_legacy_format():
    """Regression: non-NotFoundError exceptions still use the legacy
    ``RuntimeError("<OriginalType>: <message>")`` format. R5 only
    changes the unknown-tool path."""
    from amazon_ads_mcp.server.code_mode import (
        translate_to_sandbox_runtime_error,
    )

    exc = ValueError("some other failure")
    result = translate_to_sandbox_runtime_error(exc)
    text = str(result)
    try:
        parsed = json.loads(text)
        assert not (
            isinstance(parsed, dict) and parsed.get("_envelope_version") == 1
        ), f"non-NotFoundError should NOT be wrapped in envelope: {text}"
    except (TypeError, ValueError):
        pass
    assert "ValueError" in text
    assert "some other failure" in text


def test_translate_runtime_error_passthrough_preserved():
    """Regression: an existing RuntimeError is returned as-is (no
    double-wrap), per the existing contract at code_mode.py:168."""
    from amazon_ads_mcp.server.code_mode import (
        translate_to_sandbox_runtime_error,
    )

    original = RuntimeError("already wrapped")
    result = translate_to_sandbox_runtime_error(original)
    assert result is original


def test_translate_tool_error_with_envelope_passthrough_preserved():
    """Regression: a ToolError carrying v1 envelope JSON passes through
    unchanged, per the existing contract."""
    from fastmcp.exceptions import ToolError

    from amazon_ads_mcp.server.code_mode import (
        translate_to_sandbox_runtime_error,
    )

    envelope_json = json.dumps(
        {
            "_envelope_version": 1,
            "error_kind": "mcp_input_validation",
            "summary": "bad",
            "tool": "x",
            "details": [],
            "hints": [],
            "examples": [],
            "error_code": "INPUT_VALIDATION_FAILED",
            "retryable": False,
        }
    )
    exc = ToolError(envelope_json)
    result = translate_to_sandbox_runtime_error(exc)
    parsed = json.loads(str(result))
    assert parsed["error_kind"] == "mcp_input_validation"


def test_translate_unknown_tool_with_unparseable_message_still_envelope():
    """Edge: NotFoundError without the standard ``Unknown tool: <name>``
    pattern still produces a valid envelope (just with no extracted tool
    name). Don't crash if FastMCP's message format ever changes."""
    from fastmcp.exceptions import NotFoundError

    from amazon_ads_mcp.server.code_mode import (
        translate_to_sandbox_runtime_error,
    )

    exc = NotFoundError("Some unexpected error format")
    result = translate_to_sandbox_runtime_error(exc)
    parsed = json.loads(str(result))
    assert parsed["error_kind"] == "tool_not_found"
    assert "tool" in parsed
