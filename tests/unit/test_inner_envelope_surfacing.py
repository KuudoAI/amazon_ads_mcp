"""Round 8: Ads — surface inner v1 envelope through sandbox boundary.

Mirrors the SP test of the same name. When an unhandled exception
inside ``execute`` carries an inner v1 envelope JSON in its message
text (the Code Mode bridge → MontyRuntimeError → outer translator
chain), the outer envelope must surface the inner envelope rather than
wrapping it as ``internal_error`` / ``sandbox_runtime``.
"""

from __future__ import annotations

import json

from amazon_ads_mcp.middleware.error_envelope import build_envelope_from_exception


_INNER_ENVELOPE_TEMPLATE = {
    "error_kind": "mcp_input_validation",
    "tool": "set_region",
    "summary": "Tool input validation failed.",
    "details": [
        {
            "path": "region",
            "issue": "Invalid region: antarctica. Must be 'na', 'eu', or 'fe'",
            "received_type": "ValidationError",
        }
    ],
    "hints": ["set_region accepts canonical regions: 'na', 'eu', or 'fe'."],
    "examples": [],
    "error_code": "INPUT_VALIDATION_FAILED",
    "retryable": False,
    "_envelope_version": 1,
}


def test_runtime_error_carrying_inner_envelope_surfaces_inner():
    inner_json = json.dumps(_INNER_ENVELOPE_TEMPLATE)
    exc = RuntimeError(f"ToolError: {inner_json}")
    out = build_envelope_from_exception(exc, tool_name="execute")
    assert out["error_kind"] == "mcp_input_validation"
    assert out["error_code"] == "INPUT_VALIDATION_FAILED"
    assert out["details"] == _INNER_ENVELOPE_TEMPLATE["details"]
    assert "set_region accepts canonical regions" in " ".join(out["hints"])
    assert out["_envelope_version"] == 1


def test_runtime_error_carrying_raw_envelope_json_surfaces_inner():
    inner_json = json.dumps(_INNER_ENVELOPE_TEMPLATE)
    exc = RuntimeError(inner_json)
    out = build_envelope_from_exception(exc, tool_name="execute")
    assert out["error_kind"] == "mcp_input_validation"


def test_monty_style_message_text_surfaces_inner_envelope():
    inner_json = json.dumps(_INNER_ENVELOPE_TEMPLATE)
    exc = RuntimeError(f"RuntimeError: ToolError: {inner_json}")
    out = build_envelope_from_exception(exc, tool_name="execute")
    assert out["error_kind"] == "mcp_input_validation"


def test_non_envelope_runtime_error_falls_through_to_classifier():
    exc = RuntimeError("ImportError: 'urllib' not allowed")
    out = build_envelope_from_exception(exc, tool_name="execute")
    assert out["error_kind"] != "mcp_input_validation"


def test_partial_envelope_in_message_does_not_surface():
    fake = '{"error_kind": "mcp_input_validation"}'
    exc = RuntimeError(f"RuntimeError: ToolError: {fake}")
    out = build_envelope_from_exception(exc, tool_name="execute")
    assert out["error_kind"] != "mcp_input_validation"


def test_inner_envelope_is_unmodified():
    inner = dict(_INNER_ENVELOPE_TEMPLATE)
    inner["details"] = [
        {"path": "region", "issue": "Invalid region: blah", "received_type": "ValidationError"}
    ]
    exc = RuntimeError(f"ToolError: {json.dumps(inner)}")
    out = build_envelope_from_exception(exc, tool_name="execute")
    assert out["error_code"] == "INPUT_VALIDATION_FAILED"
    assert out["tool"] == inner["tool"]
    assert out["details"] == inner["details"]
