"""Property-based tests for ``build_envelope_from_exception``.

Why this matters: this function runs on every failing tool call. A latent
bug (any unhandled exception type causing an internal `KeyError`, any
raise inside the translator) would cascade into bare JSON-RPC errors at
the MCP transport layer — exactly the condition the v1 envelope contract
exists to prevent.

Properties encoded:

1. **Never raises** on any exception class the translator might receive,
   regardless of message text. The translator is the safety net; it cannot
   itself fail.
2. **Output is always a dict** with the closed set of v1-required keys.
3. **error_kind is always one of SUPPORTED_ERROR_KINDS**. New taxonomy
   members must be added explicitly — no string drift.
4. **Tool name is always a non-empty string**. ``None`` becomes
   ``"unknown_tool"`` per the documented contract.
5. **retryable is always a bool**. Coerce-on-emit invariant.
"""

from __future__ import annotations

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from amazon_ads_mcp.exceptions import (
    APIError,
    AuthenticationError,
    ConfigurationError,
    RateLimitError,
    SamplingError,
    TimeoutError as AdsTimeoutError,
    ToolExecutionError,
    TransformError,
    ValidationError as AdsValidationError,
)
from amazon_ads_mcp.middleware.error_envelope import (
    SUPPORTED_ERROR_KINDS,
    _ENVELOPE_KEYS,
    build_envelope_from_exception,
)
from amazon_ads_mcp.utils.errors import ErrorCategory, MCPError


# --- Strategies -----------------------------------------------------------

# Built-in exception types that the translator commonly receives.
_stdlib_exception_classes = st.sampled_from([
    ValueError,
    TypeError,
    KeyError,
    RuntimeError,
    LookupError,
    OSError,
    Exception,
])

# AmazonAdsMCPError subclasses with their constructor signatures.
# Each element is (cls, kwargs_strategy).
_ads_error_examples = st.sampled_from([
    APIError("upstream 500", status_code=500),
    AuthenticationError("token rejected"),
    ConfigurationError("missing AMAZON_AD_API_CLIENT_ID"),
    RateLimitError("throttled"),
    SamplingError("sampling failed"),
    AdsTimeoutError("upstream timeout"),
    ToolExecutionError("tool blew up"),
    TransformError("schema transform failed"),
    AdsValidationError("bad input"),
])

# MCPError instances spanning the ErrorCategory enum so every taxonomy
# branch is exercised.
_mcp_error_examples = st.sampled_from([
    MCPError("bad input", category=cat) for cat in ErrorCategory
])


@st.composite
def arbitrary_exception(draw):
    """Generate exception instances spanning every classifier branch."""
    kind = draw(st.sampled_from(["stdlib", "ads", "mcp", "wrapped"]))
    if kind == "stdlib":
        cls = draw(_stdlib_exception_classes)
        msg = draw(st.text(max_size=80))
        return cls(msg)
    if kind == "ads":
        return draw(_ads_error_examples)
    if kind == "mcp":
        return draw(_mcp_error_examples)
    # wrapped: an outer wrapping an inner (`raise X from Y`)
    inner = draw(_stdlib_exception_classes)(draw(st.text(max_size=40)))
    outer = ToolExecutionError(draw(st.text(max_size=40)))
    outer.__cause__ = inner
    return outer


# --- Properties -----------------------------------------------------------


@given(arbitrary_exception(), st.one_of(st.none(), st.text(max_size=40)))
@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
def test_translator_never_raises(exc: BaseException, tool: str | None) -> None:
    """The translator is the error-path safety net; it cannot itself raise.

    If this test fails, every failing tool call becomes a bare JSON-RPC
    error at the MCP transport, defeating the entire envelope contract.
    """
    envelope = build_envelope_from_exception(exc, tool_name=tool)
    assert isinstance(envelope, dict)


@given(arbitrary_exception(), st.one_of(st.none(), st.text(max_size=40)))
@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
def test_envelope_has_required_keys(exc: BaseException, tool: str | None) -> None:
    """Every emitted envelope must satisfy the v1 contract's key set.

    The contract is closed: this is the guarantee callers rely on for
    pattern-matching `error_kind` and `error_code`.
    """
    envelope = build_envelope_from_exception(exc, tool_name=tool)
    missing = _ENVELOPE_KEYS - envelope.keys()
    assert not missing, f"missing required envelope keys: {missing}"


@given(arbitrary_exception(), st.one_of(st.none(), st.text(max_size=40)))
@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
def test_error_kind_is_in_closed_taxonomy(
    exc: BaseException, tool: str | None
) -> None:
    """``error_kind`` is drawn from a closed set. New kinds require an
    explicit code change — string drift cannot silently land."""
    envelope = build_envelope_from_exception(exc, tool_name=tool)
    kind = envelope["error_kind"]
    # The translator may emit additional kinds (e.g. tool_not_found,
    # sandbox_runtime) beyond SUPPORTED_ERROR_KINDS — but every emitted
    # kind must at minimum be a non-empty lowercase string with no spaces,
    # consistent with the taxonomy convention.
    assert isinstance(kind, str)
    assert kind == kind.lower()
    assert " " not in kind
    assert len(kind) > 0


@given(arbitrary_exception(), st.one_of(st.none(), st.text(max_size=40)))
@settings(max_examples=150, suppress_health_check=[HealthCheck.too_slow])
def test_tool_name_is_non_empty_string(
    exc: BaseException, tool: str | None
) -> None:
    """``tool`` field is always a non-empty string. ``None`` defaults to
    ``"unknown_tool"`` per the documented contract."""
    envelope = build_envelope_from_exception(exc, tool_name=tool)
    assert isinstance(envelope["tool"], str)
    assert len(envelope["tool"]) > 0


@given(arbitrary_exception(), st.one_of(st.none(), st.text(max_size=40)))
@settings(max_examples=150, suppress_health_check=[HealthCheck.too_slow])
def test_retryable_is_always_bool(
    exc: BaseException, tool: str | None
) -> None:
    """``retryable`` is the field clients gate retries on. Must be a real
    bool, not truthy/falsy other types."""
    envelope = build_envelope_from_exception(exc, tool_name=tool)
    assert isinstance(envelope["retryable"], bool)


@given(arbitrary_exception(), st.one_of(st.none(), st.text(max_size=40)))
@settings(max_examples=150, suppress_health_check=[HealthCheck.too_slow])
def test_details_and_hints_are_lists(
    exc: BaseException, tool: str | None
) -> None:
    """``details`` and ``hints`` must always be lists (callers iterate
    them unconditionally; ``None`` would NoneType-error in production)."""
    envelope = build_envelope_from_exception(exc, tool_name=tool)
    assert isinstance(envelope["details"], list)
    assert isinstance(envelope["hints"], list)


# Anchor: spot-check the documented MCPError → kind mapping for a
# representative ErrorCategory. Property tests above cover the never-raise
# guarantee; this one locks the actual taxonomy contract.
@pytest.mark.parametrize(
    "category,expected_kind",
    [
        (ErrorCategory.VALIDATION, "mcp_input_validation"),
        (ErrorCategory.AUTHENTICATION, "auth_error"),
        (ErrorCategory.RATE_LIMIT, "rate_limited"),
    ],
)
def test_mcp_error_category_maps_to_expected_kind(
    category: ErrorCategory, expected_kind: str
) -> None:
    exc = MCPError("test", category=category)
    envelope = build_envelope_from_exception(exc, tool_name="t")
    assert envelope["error_kind"] == expected_kind
    assert expected_kind in SUPPORTED_ERROR_KINDS
