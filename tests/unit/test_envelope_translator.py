"""Unit tests for the v1 cross-server error envelope translator.

The translator at ``amazon_ads_mcp.middleware.error_envelope`` translates
internal Ads exceptions (``AmazonAdsMCPError`` hierarchy in ``exceptions.py``,
``MCPError`` with ``ErrorCategory`` in ``utils/errors.py``, plus stdlib
exceptions) into the v1 envelope shape defined in
``openbridge-mcp/CONTRACT.md``.

These tests are the contract for what the translator must do — written
before the translator exists. Failures here mean the implementation is
incomplete or has drifted from the contract.
"""

from __future__ import annotations

import json

import httpx
import pytest
from pydantic import BaseModel, ValidationError as PydanticValidationError


# Keep imports of the module-under-test inside tests so the test file can be
# collected even before the translator is implemented (the first run of these
# tests should *fail* with ImportError, which is what TDD wants).
def _import_translator():
    from amazon_ads_mcp.middleware import error_envelope as mod

    return mod


# ---------------------------------------------------------------------------
# Required envelope shape (v1)
# ---------------------------------------------------------------------------

REQUIRED_KEYS = {
    "error_kind",
    "tool",
    "summary",
    "details",
    "hints",
    "examples",
    "error_code",
    "retryable",
    "_envelope_version",
}


def _assert_envelope_shape(envelope: dict, *, expected_kind: str) -> None:
    assert REQUIRED_KEYS.issubset(envelope.keys()), (
        f"missing required keys: {REQUIRED_KEYS - envelope.keys()}"
    )
    assert envelope["error_kind"] == expected_kind
    assert isinstance(envelope["details"], list)
    assert isinstance(envelope["hints"], list)
    assert isinstance(envelope["examples"], list)
    assert isinstance(envelope["retryable"], bool)
    assert envelope["_envelope_version"] == 1


# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

def test_envelope_version_is_one():
    mod = _import_translator()
    assert mod.ENVELOPE_VERSION == 1


def test_supported_error_kinds_match_ads_subset():
    """Ads emits a subset of the master taxonomy. Verify the supported set."""
    mod = _import_translator()
    expected = {
        "mcp_input_validation",
        "ads_api_http",
        "auth_error",
        "rate_limited",
        "internal_error",
    }
    assert expected.issubset(set(mod.SUPPORTED_ERROR_KINDS))


# ---------------------------------------------------------------------------
# Pydantic / FastMCP validation → mcp_input_validation
# ---------------------------------------------------------------------------

class _NeedsInt(BaseModel):
    value: int


def test_pydantic_validation_error_maps_to_mcp_input_validation():
    mod = _import_translator()
    try:
        _NeedsInt(value="not_an_int")
    except PydanticValidationError as exc:
        envelope = mod.build_envelope_from_exception(exc, tool_name="adsv1_create_campaign")

    _assert_envelope_shape(envelope, expected_kind="mcp_input_validation")
    assert envelope["tool"] == "adsv1_create_campaign"
    assert envelope["retryable"] is False
    assert envelope["error_code"] == "INPUT_VALIDATION_FAILED"
    # Path comes through dotted
    assert any(d.get("path") == "value" for d in envelope["details"])


# ---------------------------------------------------------------------------
# AmazonAdsMCPError hierarchy mappings
# ---------------------------------------------------------------------------

def test_authentication_error_maps_to_auth_error():
    mod = _import_translator()
    from amazon_ads_mcp.exceptions import AuthenticationError

    exc = AuthenticationError("Bad token", details={"reason": "expired"})
    envelope = mod.build_envelope_from_exception(exc, tool_name="set_active_profile")
    _assert_envelope_shape(envelope, expected_kind="auth_error")
    assert envelope["retryable"] is False  # auth errors are not retryable without action


def test_oauth_error_maps_to_auth_error():
    mod = _import_translator()
    from amazon_ads_mcp.exceptions import OAuthError

    exc = OAuthError("Invalid grant", error_code="invalid_grant")
    envelope = mod.build_envelope_from_exception(exc, tool_name="oauth_callback")
    _assert_envelope_shape(envelope, expected_kind="auth_error")


def test_token_error_maps_to_auth_error():
    mod = _import_translator()
    from amazon_ads_mcp.exceptions import TokenError

    exc = TokenError("Refresh failed", token_type="refresh")
    envelope = mod.build_envelope_from_exception(exc, tool_name="set_active_profile")
    _assert_envelope_shape(envelope, expected_kind="auth_error")


def test_rate_limit_error_maps_to_rate_limited():
    mod = _import_translator()
    from amazon_ads_mcp.exceptions import RateLimitError

    exc = RateLimitError("Throttled", retry_after=60, limit=10)
    envelope = mod.build_envelope_from_exception(exc, tool_name="adsv1_list_reports")
    _assert_envelope_shape(envelope, expected_kind="rate_limited")
    assert envelope["retryable"] is True


def test_timeout_error_maps_to_ads_api_http():
    mod = _import_translator()
    from amazon_ads_mcp.exceptions import TimeoutError as AdsTimeoutError

    exc = AdsTimeoutError("Request timed out", operation="get_campaigns")
    envelope = mod.build_envelope_from_exception(exc, tool_name="adsv1_list_campaigns")
    _assert_envelope_shape(envelope, expected_kind="ads_api_http")
    assert envelope["retryable"] is True  # timeouts are retryable


def test_api_error_maps_to_ads_api_http():
    mod = _import_translator()
    from amazon_ads_mcp.exceptions import APIError

    exc = APIError("Bad gateway", status_code=502, response_body='{"error":"upstream"}')
    envelope = mod.build_envelope_from_exception(exc, tool_name="adsv1_list_campaigns")
    _assert_envelope_shape(envelope, expected_kind="ads_api_http")
    assert envelope["error_code"].endswith("502")


def test_validation_error_from_amazon_ads_mcp_maps_to_mcp_input_validation():
    mod = _import_translator()
    from amazon_ads_mcp.exceptions import ValidationError as AdsValidationError

    exc = AdsValidationError("Bad input", field="campaign_id", value=42)
    envelope = mod.build_envelope_from_exception(exc, tool_name="adsv1_get_campaign")
    _assert_envelope_shape(envelope, expected_kind="mcp_input_validation")
    assert envelope["retryable"] is False


def test_configuration_error_maps_to_internal_error():
    mod = _import_translator()
    from amazon_ads_mcp.exceptions import ConfigurationError

    exc = ConfigurationError("Missing config", setting="API_TOKEN")
    envelope = mod.build_envelope_from_exception(exc, tool_name=None)
    _assert_envelope_shape(envelope, expected_kind="internal_error")


def test_tool_execution_error_unwraps_original():
    """ToolExecutionError wraps another error; translator should peel and reclassify."""
    mod = _import_translator()
    from amazon_ads_mcp.exceptions import (
        AuthenticationError,
        ToolExecutionError,
    )

    original = AuthenticationError("Bad token")
    exc = ToolExecutionError("Tool failed", tool_name="x", original_error=original)
    # The wrapper carries the original via details["error_type"]; translator
    # may unwrap or treat ToolExecutionError as internal_error. Allow either
    # internal_error OR auth_error, but require deterministic behavior with
    # error_type recorded in details.
    envelope = mod.build_envelope_from_exception(exc, tool_name="x")
    assert envelope["error_kind"] in ("internal_error", "auth_error")
    assert envelope["_envelope_version"] == 1


# ---------------------------------------------------------------------------
# MCPError + ErrorCategory mappings (utils/errors.py)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "category,expected_kind,expected_retryable",
    [
        ("AUTHENTICATION", "auth_error", False),
        ("PERMISSION", "auth_error", False),
        ("VALIDATION", "mcp_input_validation", False),
        ("NETWORK", "ads_api_http", True),
        ("EXTERNAL_SERVICE", "ads_api_http", True),
        ("NOT_FOUND", "ads_api_http", False),
        ("RATE_LIMIT", "rate_limited", True),
        ("INTERNAL", "internal_error", False),
        ("DATABASE", "internal_error", False),
    ],
)
def test_mcp_error_category_mappings(category, expected_kind, expected_retryable):
    mod = _import_translator()
    from amazon_ads_mcp.utils.errors import ErrorCategory, MCPError

    exc = MCPError(
        message=f"{category} failed",
        category=ErrorCategory(category.lower()),
        status_code=500,
        details={"path": "x"},
    )
    envelope = mod.build_envelope_from_exception(exc, tool_name="t")
    _assert_envelope_shape(envelope, expected_kind=expected_kind)
    assert envelope["retryable"] is expected_retryable


def test_mcp_error_all_nine_categories_have_explicit_mapping():
    """Every ErrorCategory member must have an explicit mapping; no fallthrough."""
    mod = _import_translator()
    from amazon_ads_mcp.utils.errors import ErrorCategory, MCPError

    for member in ErrorCategory:
        exc = MCPError(message="x", category=member, status_code=500)
        envelope = mod.build_envelope_from_exception(exc, tool_name="t")
        # Every category must produce a known error_kind
        assert envelope["error_kind"] in mod.SUPPORTED_ERROR_KINDS, (
            f"ErrorCategory.{member.name} -> {envelope['error_kind']} "
            f"is not in SUPPORTED_ERROR_KINDS"
        )


# ---------------------------------------------------------------------------
# httpx HTTP errors
# ---------------------------------------------------------------------------

def test_http_status_error_400_maps_to_ads_api_http():
    mod = _import_translator()
    request = httpx.Request("GET", "https://advertising-api.amazon.com/v2/profiles")
    response = httpx.Response(
        400,
        request=request,
        json={"code": "INVALID_INPUT", "details": "bad campaign id"},
    )
    exc = httpx.HTTPStatusError("bad", request=request, response=response)
    envelope = mod.build_envelope_from_exception(exc, tool_name="adsv1_get_campaign")
    _assert_envelope_shape(envelope, expected_kind="ads_api_http")
    assert envelope["error_code"] == "ADS_API_HTTP_400"
    assert envelope["retryable"] is False


def test_http_status_error_429_maps_to_rate_limited():
    mod = _import_translator()
    request = httpx.Request("GET", "https://advertising-api.amazon.com/v2/campaigns")
    response = httpx.Response(429, request=request, headers={"retry-after": "30"})
    exc = httpx.HTTPStatusError("throttled", request=request, response=response)
    envelope = mod.build_envelope_from_exception(exc, tool_name="adsv1_list_campaigns")
    _assert_envelope_shape(envelope, expected_kind="rate_limited")
    assert envelope["retryable"] is True
    assert envelope["error_code"] == "ADS_API_HTTP_429"


def test_http_status_error_5xx_is_retryable():
    mod = _import_translator()
    request = httpx.Request("GET", "https://advertising-api.amazon.com/v2/campaigns")
    response = httpx.Response(503, request=request)
    exc = httpx.HTTPStatusError("unavailable", request=request, response=response)
    envelope = mod.build_envelope_from_exception(exc, tool_name="adsv1_list_campaigns")
    _assert_envelope_shape(envelope, expected_kind="ads_api_http")
    assert envelope["retryable"] is True


# ---------------------------------------------------------------------------
# Generic exception → internal_error
# ---------------------------------------------------------------------------

def test_bare_runtime_error_maps_to_internal_error():
    mod = _import_translator()
    exc = RuntimeError("unexpected boom")
    envelope = mod.build_envelope_from_exception(exc, tool_name="t")
    _assert_envelope_shape(envelope, expected_kind="internal_error")
    assert envelope["retryable"] is False


# ---------------------------------------------------------------------------
# Tool name handling
# ---------------------------------------------------------------------------

def test_missing_tool_name_uses_unknown_tool_default():
    mod = _import_translator()
    exc = RuntimeError("boom")
    envelope = mod.build_envelope_from_exception(exc, tool_name=None)
    assert envelope["tool"] == "unknown_tool"


# ---------------------------------------------------------------------------
# legacy_error_kind for migration window
# ---------------------------------------------------------------------------

def test_legacy_error_kind_emitted_when_requested():
    """During the one-release migration window the translator emits
    `legacy_error_kind` carrying the prior `category` enum string value.
    """
    mod = _import_translator()
    from amazon_ads_mcp.utils.errors import ErrorCategory, MCPError

    exc = MCPError(
        message="auth failed",
        category=ErrorCategory.AUTHENTICATION,
        status_code=401,
    )
    envelope = mod.build_envelope_from_exception(
        exc, tool_name="t", emit_legacy_error_kind=True
    )
    assert envelope["legacy_error_kind"] == "authentication"


def test_legacy_error_kind_absent_by_default():
    mod = _import_translator()
    from amazon_ads_mcp.utils.errors import ErrorCategory, MCPError

    exc = MCPError(message="auth failed", category=ErrorCategory.AUTHENTICATION)
    envelope = mod.build_envelope_from_exception(exc, tool_name="t")
    assert "legacy_error_kind" not in envelope


# ---------------------------------------------------------------------------
# _meta plumbing
# ---------------------------------------------------------------------------

def test_meta_normalized_threaded_into_envelope():
    """If the upstream middleware captured normalization events, they appear
    in the error envelope's `_meta.normalized` block."""
    mod = _import_translator()
    exc = RuntimeError("boom")
    normalized = [
        {"kind": "renamed", "from": "CampaignId", "to": "campaignId", "reason": "schema_canonical_key"},
    ]
    envelope = mod.build_envelope_from_exception(
        exc, tool_name="t", normalized=normalized
    )
    assert envelope.get("_meta", {}).get("normalized") == normalized


def test_meta_rate_limit_threaded_when_provided():
    mod = _import_translator()
    from amazon_ads_mcp.exceptions import RateLimitError

    exc = RateLimitError("throttled", retry_after=12)
    envelope = mod.build_envelope_from_exception(
        exc,
        tool_name="t",
        http_meta={
            "rate_limit": {"limit_per_second": 1.0, "remaining": 0, "reset_at": "2026-04-25T18:00:00Z"},
            "retry_after_seconds": 12.0,
        },
    )
    rate = envelope["_meta"]["rate_limit"]
    assert rate["limit_per_second"] == 1.0
    assert envelope["_meta"]["retry_after_seconds"] == 12.0


def test_meta_omitted_when_no_telemetry():
    """Clean errors with no normalization or http_meta have no `_meta`."""
    mod = _import_translator()
    exc = RuntimeError("boom")
    envelope = mod.build_envelope_from_exception(exc, tool_name="t")
    assert "_meta" not in envelope


# ---------------------------------------------------------------------------
# JSON-serializable, schema-conformant
# ---------------------------------------------------------------------------

def test_envelope_is_json_serializable():
    mod = _import_translator()
    exc = RuntimeError("boom")
    envelope = mod.build_envelope_from_exception(exc, tool_name="t")
    # Must round-trip through JSON
    text = json.dumps(envelope)
    assert json.loads(text) == envelope


# ---------------------------------------------------------------------------
# Envelope detection (idempotency)
# ---------------------------------------------------------------------------

def test_is_envelope_text_recognizes_v1_envelope():
    mod = _import_translator()
    envelope = {
        "error_kind": "internal_error",
        "tool": "t",
        "summary": "x",
        "details": [],
        "hints": [],
        "examples": [],
        "error_code": "X",
        "retryable": False,
        "_envelope_version": 1,
    }
    assert mod.is_envelope_text(json.dumps(envelope)) is True


def test_is_envelope_text_rejects_unstructured_json():
    mod = _import_translator()
    assert mod.is_envelope_text('{"foo": "bar"}') is False
    assert mod.is_envelope_text("not json") is False


# ---------------------------------------------------------------------------
# B2: tool_not_found hints must point at real discovery tools
# ---------------------------------------------------------------------------


def test_tool_not_found_hints_name_real_discovery_tools():
    """When NotFoundError is classified, the envelope hints must name
    the actual discovery surface registered by Code Mode (GetTags,
    Search, GetSchemas) - not the fictional list_tools / tool_search.
    """
    from fastmcp.exceptions import NotFoundError

    mod = _import_translator()
    exc = NotFoundError("Unknown tool: listIdentities")
    envelope = mod.build_envelope_from_exception(exc, tool_name="listIdentities")

    assert envelope["error_kind"] == "tool_not_found"
    assert envelope["error_code"] == "TOOL_NOT_FOUND"

    hint_text = " ".join(envelope["hints"])
    # Real discovery surface registered by build_discovery_tools().
    # FastMCP's GetTags/Search/GetSchemas classes register under the
    # lowercase tool names tags/search/get_schema (verified live via
    # list_tools on a running server).
    assert "tags" in hint_text
    assert "search" in hint_text
    assert "get_schema" in hint_text
    # Stale references must NOT appear
    assert "list_tools" not in hint_text
    assert "tool_search" not in hint_text


# ---------------------------------------------------------------------------
# B3: Monty sandbox blocked imports → sandbox_runtime, not internal_error
# ---------------------------------------------------------------------------


def _make_monty_stub(*, name: str = "MontyRuntimeError"):
    """Build a stand-in for ``pydantic_monty.MontyRuntimeError``.

    The real Monty exceptions live in a compiled Rust extension and
    can't be constructed directly from Python. The classifier uses
    duck-typing on ``cls.__module__`` + ``cls.__name__`` so this stub
    presents the same wire shape (right module path, right class name,
    same ``.exception()`` accessor) without depending on the compiled
    extension.
    """

    def __init__(self, inner: BaseException):
        Exception.__init__(self, str(inner))
        self._inner = inner

    def exception(self) -> BaseException:
        return self._inner

    cls = type(
        name,
        (Exception,),
        {
            "__module__": "pydantic_monty._monty",
            "__init__": __init__,
            "exception": exception,
        },
    )
    return cls


_StubMontyRuntimeError = _make_monty_stub(name="MontyRuntimeError")
_StubMontyError = _make_monty_stub(name="MontyError")


def test_module_not_found_in_sandbox_classified_as_sandbox_runtime():
    """B3: when a Code Mode sandbox script triggers a ModuleNotFoundError
    (e.g. ``from collections import Counter``), the envelope must surface
    the typed ``sandbox_runtime`` error_kind from CONTRACT.md — NOT the
    generic ``internal_error`` that prior versions emitted."""
    mod = _import_translator()

    inner = ModuleNotFoundError("No module named 'collections'")
    inner.name = "collections"
    exc = _StubMontyRuntimeError(inner)

    envelope = mod.build_envelope_from_exception(exc, tool_name="execute")

    assert envelope["error_kind"] == "sandbox_runtime"
    assert envelope["error_code"] == "SANDBOX_MODULE_BLOCKED"
    # Names the blocked module so agents can react
    assert "collections" in envelope["summary"]
    # Hints must point at the real workaround (built-ins, call_tool)
    hint_text = " ".join(envelope["hints"])
    assert "call_tool" in hint_text


def test_other_monty_runtime_error_still_classified_as_sandbox_runtime():
    """Non-import MontyRuntimeError causes still route to ``sandbox_runtime``
    — just with the more general ``SANDBOX_RUNTIME_ERROR`` error_code so
    agents can branch on cause."""
    mod = _import_translator()

    inner = AttributeError("module 'asyncio' has no attribute 'sleep'")
    exc = _StubMontyRuntimeError(inner)

    envelope = mod.build_envelope_from_exception(exc, tool_name="execute")

    assert envelope["error_kind"] == "sandbox_runtime"
    assert envelope["error_code"] == "SANDBOX_RUNTIME_ERROR"


def test_non_monty_module_not_found_stays_internal_error():
    """Defensive: a bare ModuleNotFoundError that did NOT come from the
    Monty sandbox (e.g. a server-side import bug at runtime) should
    still classify as ``internal_error`` — we must not over-promote
    every ModuleNotFoundError to sandbox_runtime."""
    mod = _import_translator()

    exc = ModuleNotFoundError("No module named 'broken_optional_dep'")

    envelope = mod.build_envelope_from_exception(exc, tool_name="some_tool")

    # Stays in the bare-Exception bucket because it isn't a MontyError.
    assert envelope["error_kind"] == "internal_error"
    assert envelope["error_code"] == "INTERNAL_ERROR"


def test_execute_description_documents_sandbox_runtime_error_kind():
    """The ``EXECUTE_DESCRIPTION`` must tell agents:

    1. The correct exception class to catch INSIDE the sandbox for a
       blocked import — stock ``ImportError``, not ``RuntimeError``.
       (Wire-probe verified against the running server: client-side
       feedback flagged this as a docstring-vs-reality mismatch.)
    2. That the v1 ``sandbox_runtime`` / ``SANDBOX_MODULE_BLOCKED``
       envelope only fires when the error is uncaught and propagates
       OUT of ``execute``.
    3. Concrete ground-truth lists of available vs blocked stdlib and
       missing builtins, with workarounds for the surprising gaps
       (hasattr, callable).
    """
    from amazon_ads_mcp.server.code_mode import EXECUTE_DESCRIPTION

    text = EXECUTE_DESCRIPTION
    # Envelope kind and code are still documented (uncaught path)
    assert "sandbox_runtime" in text
    assert "SANDBOX_MODULE_BLOCKED" in text
    # Critical correction: agents must see ImportError as the in-sandbox catch
    assert "ImportError" in text
    # Ground-truth lists must name verified-blocked stdlib so agents stop
    # discovering by trial-and-error
    assert "collections" in text
    # Verified-missing builtins with workarounds — the most surprising gaps
    assert "hasattr" in text
    assert "callable" in text
    # Predictive-model bullet (round-3 client feedback): the sentinel
    # pattern is module-only; built-in methods and function attributes
    # are invokable but not reachable as attributes. Pin the agent-
    # facing summary phrasing.
    assert "knows the shape of its inputs" in text
    # Negative regression: the prior shallow framing implied direct
    # attribute access works on built-in instances (it doesn't).
    assert "direct attribute access works" not in text
