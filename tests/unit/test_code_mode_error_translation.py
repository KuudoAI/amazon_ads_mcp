"""Unit tests for Code Mode → sandbox error translation under the v1 contract.

When a tool call inside ``execute`` fails, the envelope middleware has
already transformed the exception into a ``ToolError`` whose body is the v1
envelope JSON. The Code Mode auth bridge wraps that ``ToolError`` and
re-raises a ``RuntimeError`` so the sandbox's ``try/except RuntimeError:``
can catch it.

Contract (no-double-wrap rule):

- For envelope-shaped ``ToolError`` — translate to
  ``RuntimeError(f"{error_kind}: {summary}")``. The full envelope is NOT
  re-nested as JSON inside the message; agents that need the structured
  envelope catch on the *outside* of ``execute``.
- For non-envelope exceptions — keep the legacy
  ``RuntimeError(f"{TypeName}: {message}")`` form.
- The ``EXECUTE_DESCRIPTION`` string must accurately describe what agents
  see in the sandbox.
"""

from __future__ import annotations

import json

from fastmcp.exceptions import ToolError


def _v1_envelope(*, error_kind: str = "ads_api_http", summary: str = "boom") -> dict:
    return {
        "error_kind": error_kind,
        "tool": "t",
        "summary": summary,
        "details": [],
        "hints": [],
        "examples": [],
        "error_code": "X",
        "retryable": False,
        "_envelope_version": 1,
    }


# ---------------------------------------------------------------------------
# Translation helper exists and is importable
# ---------------------------------------------------------------------------


def test_translate_to_sandbox_runtime_error_is_exposed():
    from amazon_ads_mcp.server import code_mode

    assert hasattr(code_mode, "translate_to_sandbox_runtime_error")


# ---------------------------------------------------------------------------
# Envelope ToolError → RuntimeError("<error_kind>: <summary>")
# ---------------------------------------------------------------------------


def test_envelope_tool_error_passes_through_full_envelope_json():
    """Cross-server symmetry: agents inside ``execute`` need the full
    structured envelope (hints, error_code, retryable, _meta) to make
    recovery decisions. Mirrors SP behavior."""
    from amazon_ads_mcp.server.code_mode import translate_to_sandbox_runtime_error

    env = _v1_envelope(error_kind="auth_error", summary="Bad token.")
    env["hints"] = ["Re-authorize the active identity if expired."]
    exc = ToolError(json.dumps(env))
    runtime = translate_to_sandbox_runtime_error(exc)

    assert isinstance(runtime, RuntimeError)
    parsed = json.loads(str(runtime))
    assert parsed["error_kind"] == "auth_error"
    assert parsed["summary"] == "Bad token."
    assert parsed["hints"] == ["Re-authorize the active identity if expired."]
    assert parsed["_envelope_version"] == 1


def test_envelope_tool_error_preserves_meta_block():
    """``_meta`` (rate_limit, normalized, warnings) must be inspectable
    by agents recovering inside ``execute``."""
    from amazon_ads_mcp.server.code_mode import translate_to_sandbox_runtime_error

    env = _v1_envelope(error_kind="rate_limited", summary="Throttled.")
    env["_meta"] = {
        "rate_limit": {"limit_per_second": 10.0, "remaining": 0.0},
        "retry_after_seconds": 30.0,
    }
    runtime = translate_to_sandbox_runtime_error(ToolError(json.dumps(env)))

    parsed = json.loads(str(runtime))
    assert parsed["_meta"]["rate_limit"]["remaining"] == 0.0
    assert parsed["_meta"]["retry_after_seconds"] == 30.0


# ---------------------------------------------------------------------------
# Non-envelope ToolError → RuntimeError("ToolError: <text>")
# ---------------------------------------------------------------------------


def test_non_envelope_tool_error_falls_back_to_classic_form():
    from amazon_ads_mcp.server.code_mode import translate_to_sandbox_runtime_error

    exc = ToolError("plain text error message")
    runtime = translate_to_sandbox_runtime_error(exc)

    assert isinstance(runtime, RuntimeError)
    assert str(runtime) == "ToolError: plain text error message"


# ---------------------------------------------------------------------------
# Generic exception → RuntimeError("<TypeName>: <message>")
# ---------------------------------------------------------------------------


def test_generic_exception_translates_to_type_name_form():
    from amazon_ads_mcp.server.code_mode import translate_to_sandbox_runtime_error

    runtime = translate_to_sandbox_runtime_error(ValueError("bad value"))
    assert isinstance(runtime, RuntimeError)
    assert str(runtime) == "ValueError: bad value"


# ---------------------------------------------------------------------------
# RuntimeError already - pass through (avoid double wrapping)
# ---------------------------------------------------------------------------


def test_existing_runtime_error_is_not_double_wrapped():
    from amazon_ads_mcp.server.code_mode import translate_to_sandbox_runtime_error

    original = RuntimeError("already a runtime error")
    result = translate_to_sandbox_runtime_error(original)
    # Must be a RuntimeError; if it's a fresh wrapper its message must reflect
    # the original type+text, not a nested RuntimeError-in-RuntimeError.
    assert isinstance(result, RuntimeError)
    assert "RuntimeError: already a runtime error" == str(result) or result is original


# ---------------------------------------------------------------------------
# Description string is in sync with translation behavior
# ---------------------------------------------------------------------------


def test_execute_description_documents_envelope_translation():
    """The EXECUTE_DESCRIPTION must tell agents how to extract the
    structured envelope from a caught RuntimeError inside the sandbox."""
    from amazon_ads_mcp.server.code_mode import EXECUTE_DESCRIPTION

    text = EXECUTE_DESCRIPTION
    # Mention the envelope contract
    assert "envelope" in text.lower()
    # Show agents the json.loads pattern for unpacking it
    assert "json.loads" in text
    # Mention RuntimeError as the catch surface
    assert "RuntimeError" in text
