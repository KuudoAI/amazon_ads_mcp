"""Unit tests for the v1 error envelope FastMCP middleware.

The middleware at ``amazon_ads_mcp.middleware.error_envelope_middleware``
wraps tool dispatch. It catches any exception raised by downstream tools
and translates it into a v1 envelope ``ToolError`` using
``build_envelope_from_exception``. It also threads any captured pre-flight
normalization events into ``_meta.normalized``.

Behavior:

- Successful calls pass through untouched
- Exceptions become ``ToolError(envelope_json)``
- Already-enveloped ``ToolError`` exceptions pass through unchanged (idempotency)
- ``_meta.normalized`` events from the schema-normalization middleware are
  threaded into the envelope when set
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from fastmcp.exceptions import ToolError


def _make_context(tool_name: str = "t") -> SimpleNamespace:
    """Minimal MiddlewareContext-shaped object for the on_call_tool path."""
    message = SimpleNamespace(name=tool_name, arguments={})
    return SimpleNamespace(message=message, fastmcp_context=None)


# ---------------------------------------------------------------------------
# Module surface
# ---------------------------------------------------------------------------


def test_module_exposes_envelope_middleware():
    from amazon_ads_mcp.middleware import error_envelope_middleware as mod

    assert hasattr(mod, "ErrorEnvelopeMiddleware")
    assert hasattr(mod, "create_error_envelope_middleware")


# ---------------------------------------------------------------------------
# Pass-through on success
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_successful_call_passes_through_untouched():
    from amazon_ads_mcp.middleware.error_envelope_middleware import (
        ErrorEnvelopeMiddleware,
    )

    middleware = ErrorEnvelopeMiddleware()
    expected = {"data": "ok"}

    async def call_next(_ctx):
        return expected

    result = await middleware.on_call_tool(_make_context(), call_next)
    assert result is expected


# ---------------------------------------------------------------------------
# Exceptions become v1 envelopes
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_runtime_error_becomes_v1_envelope():
    from amazon_ads_mcp.middleware.error_envelope_middleware import (
        ErrorEnvelopeMiddleware,
    )

    middleware = ErrorEnvelopeMiddleware()

    async def call_next(_ctx):
        raise RuntimeError("boom")

    with pytest.raises(ToolError) as exc_info:
        await middleware.on_call_tool(_make_context("adsv1_get_campaign"), call_next)
    envelope = json.loads(str(exc_info.value))
    assert envelope["error_kind"] == "internal_error"
    assert envelope["tool"] == "adsv1_get_campaign"
    assert envelope["_envelope_version"] == 1


@pytest.mark.asyncio
async def test_authentication_error_becomes_auth_error_envelope():
    from amazon_ads_mcp.exceptions import AuthenticationError
    from amazon_ads_mcp.middleware.error_envelope_middleware import (
        ErrorEnvelopeMiddleware,
    )

    middleware = ErrorEnvelopeMiddleware()

    async def call_next(_ctx):
        raise AuthenticationError("bad token")

    with pytest.raises(ToolError) as exc_info:
        await middleware.on_call_tool(_make_context("set_active_profile"), call_next)
    envelope = json.loads(str(exc_info.value))
    assert envelope["error_kind"] == "auth_error"


# ---------------------------------------------------------------------------
# Idempotency — already-enveloped ToolError passes through
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_already_enveloped_tool_error_passes_through():
    from amazon_ads_mcp.middleware.error_envelope_middleware import (
        ErrorEnvelopeMiddleware,
    )

    middleware = ErrorEnvelopeMiddleware()

    pre_envelope = {
        "error_kind": "internal_error",
        "tool": "x",
        "summary": "y",
        "details": [],
        "hints": [],
        "examples": [],
        "error_code": "X",
        "retryable": False,
        "_envelope_version": 1,
    }
    pre_envelope_text = json.dumps(pre_envelope)

    async def call_next(_ctx):
        raise ToolError(pre_envelope_text)

    with pytest.raises(ToolError) as exc_info:
        await middleware.on_call_tool(_make_context(), call_next)

    # The exception text is preserved exactly — no re-envelope wrap.
    assert str(exc_info.value) == pre_envelope_text


# ---------------------------------------------------------------------------
# _meta.normalized threaded from the schema normalization layer
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_meta_normalized_threaded_into_envelope_on_failure():
    from amazon_ads_mcp.middleware.error_envelope_middleware import (
        ErrorEnvelopeMiddleware,
    )
    from amazon_ads_mcp.middleware.schema_normalization import (
        _CURRENT_NORMALIZATION_EVENTS,
    )

    middleware = ErrorEnvelopeMiddleware()

    events = [
        {"kind": "renamed", "from": "CampaignId", "to": "campaignId", "reason": "schema_canonical_key"},
    ]
    token = _CURRENT_NORMALIZATION_EVENTS.set(events)
    try:

        async def call_next(_ctx):
            raise RuntimeError("boom")

        with pytest.raises(ToolError) as exc_info:
            await middleware.on_call_tool(_make_context("t"), call_next)
        envelope = json.loads(str(exc_info.value))
        assert envelope.get("_meta", {}).get("normalized") == events
    finally:
        _CURRENT_NORMALIZATION_EVENTS.reset(token)


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def test_create_error_envelope_middleware_returns_middleware_instance():
    from amazon_ads_mcp.middleware.error_envelope_middleware import (
        ErrorEnvelopeMiddleware,
        create_error_envelope_middleware,
    )

    instance = create_error_envelope_middleware()
    assert isinstance(instance, ErrorEnvelopeMiddleware)
