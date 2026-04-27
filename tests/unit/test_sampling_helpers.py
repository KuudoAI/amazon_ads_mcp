"""Unit tests for ``sample_with_fallback``.

This module sat at 0% coverage in round 13's coverage measurement (51
statements, the largest single uncovered module). Coverage push targets
the documented branches:

1. Happy path — client supports sampling.
2. Client doesn't support sampling, falls back to server-side handler.
3. Client doesn't support sampling AND no fallback → informative raise.
4. Different client error → re-raised verbatim.
5. Message-shape coercions (str, list[str], list[SamplingMessage]).
6. Model-preferences coercion (str, list[str]).

These are example-based tests; a property test on this surface would buy
little because the function's contract is mostly exception routing and
shape coercion, both of which read better as concrete cases.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from mcp.types import SamplingMessage, TextContent

from amazon_ads_mcp.utils.sampling_helpers import sample_with_fallback


# --- Helpers --------------------------------------------------------------


def _make_ctx(
    *, sample_result=None, sample_raises=None, fallback_handler=None
) -> MagicMock:
    """Build a minimal Context-like double for sample_with_fallback.

    Note: deliberately uses bare MagicMock (no spec) — the function under
    test reads only ``ctx.sample``, ``ctx.get_sampling_handler``, and
    ``ctx.request_context``. Spec'ing against the real fastmcp.Context
    pulls in pydantic machinery that adds noise without catching real
    drift on the small surface we touch.
    """
    ctx = MagicMock()
    if sample_raises is not None:
        ctx.sample = AsyncMock(side_effect=sample_raises)
    else:
        ctx.sample = AsyncMock(return_value=sample_result)
    if fallback_handler is None:
        ctx.get_sampling_handler = MagicMock(return_value=None)
    else:
        ctx.get_sampling_handler = MagicMock(return_value=fallback_handler)
    ctx.request_context = MagicMock(name="request_context")
    return ctx


# --- Happy path -----------------------------------------------------------


@pytest.mark.asyncio
async def test_client_sampling_happy_path() -> None:
    """When ctx.sample succeeds, the result is returned and the fallback
    handler is never consulted."""
    expected = TextContent(type="text", text="hello")
    ctx = _make_ctx(sample_result=expected)

    result = await sample_with_fallback(ctx, "ping")

    assert result is expected
    ctx.sample.assert_awaited_once()
    ctx.get_sampling_handler.assert_not_called()


# --- "Client doesn't support sampling" → fallback -------------------------


@pytest.mark.asyncio
async def test_falls_back_to_server_handler_when_client_unsupported() -> None:
    """When the client raises 'does not support sampling', the server-side
    fallback handler is invoked."""
    fallback_result = MagicMock(content=TextContent(type="text", text="fallback"))
    fallback = AsyncMock(return_value=fallback_result)

    ctx = _make_ctx(
        sample_raises=Exception("Client does not support sampling"),
        fallback_handler=fallback,
    )

    result = await sample_with_fallback(ctx, "ping")

    assert result.text == "fallback"
    fallback.assert_awaited_once()


@pytest.mark.asyncio
async def test_falls_back_with_list_of_strings() -> None:
    """List-of-strings input is coerced to SamplingMessage list at the
    fallback boundary."""
    fallback_result = MagicMock(content=TextContent(type="text", text="ok"))
    fallback = AsyncMock(return_value=fallback_result)

    ctx = _make_ctx(
        sample_raises=Exception("sampling not supported"),
        fallback_handler=fallback,
    )

    await sample_with_fallback(ctx, ["one", "two"])

    sent_messages = fallback.await_args.args[0]
    assert len(sent_messages) == 2
    assert all(isinstance(m, SamplingMessage) for m in sent_messages)
    assert sent_messages[0].content.text == "one"
    assert sent_messages[1].content.text == "two"


@pytest.mark.asyncio
async def test_falls_back_preserves_existing_sampling_messages() -> None:
    """Pre-built SamplingMessage objects in the list are preserved as-is."""
    fallback_result = MagicMock(content="result")
    fallback = AsyncMock(return_value=fallback_result)
    pre_built = SamplingMessage(
        role="user", content=TextContent(type="text", text="precooked")
    )

    ctx = _make_ctx(
        sample_raises=Exception("Client does not support sampling"),
        fallback_handler=fallback,
    )

    await sample_with_fallback(ctx, [pre_built])

    sent_messages = fallback.await_args.args[0]
    assert sent_messages[0] is pre_built  # identity preserved


@pytest.mark.asyncio
async def test_no_fallback_handler_raises_informative_error() -> None:
    """When client doesn't support sampling AND no fallback is wired,
    the raise must guide the user to enable server-side sampling."""
    ctx = _make_ctx(
        sample_raises=Exception("Client does not support sampling"),
        fallback_handler=None,
    )

    with pytest.raises(Exception, match="Client does not support sampling"):
        await sample_with_fallback(ctx, "ping")


# --- Different errors are re-raised ---------------------------------------


@pytest.mark.asyncio
async def test_unrelated_client_error_is_reraised() -> None:
    """Errors that aren't 'does not support sampling' must propagate
    untouched — masking them would hide real bugs (auth failures, network
    errors, etc.) under the fallback path."""
    original = RuntimeError("network glitch — totally unrelated")
    ctx = _make_ctx(sample_raises=original)

    with pytest.raises(RuntimeError, match="network glitch"):
        await sample_with_fallback(ctx, "ping")

    # Fallback path was never consulted
    ctx.get_sampling_handler.assert_not_called()


# --- Model preferences coercion ------------------------------------------


@pytest.mark.asyncio
async def test_model_preferences_string_becomes_hint() -> None:
    """A bare string model preference is wrapped as a single-hint dict."""
    fallback_result = MagicMock(content="ok")
    fallback = AsyncMock(return_value=fallback_result)

    ctx = _make_ctx(
        sample_raises=Exception("Client does not support sampling"),
        fallback_handler=fallback,
    )

    await sample_with_fallback(ctx, "ping", model_preferences="claude-haiku")

    params = fallback.await_args.args[1]
    assert params.modelPreferences == {"hints": [{"name": "claude-haiku"}]}


@pytest.mark.asyncio
async def test_model_preferences_list_becomes_hints() -> None:
    """A list of model preferences becomes a multi-hint dict."""
    fallback_result = MagicMock(content="ok")
    fallback = AsyncMock(return_value=fallback_result)

    ctx = _make_ctx(
        sample_raises=Exception("Client does not support sampling"),
        fallback_handler=fallback,
    )

    await sample_with_fallback(
        ctx, "ping", model_preferences=["claude-opus", "claude-sonnet"]
    )

    params = fallback.await_args.args[1]
    assert params.modelPreferences == {
        "hints": [{"name": "claude-opus"}, {"name": "claude-sonnet"}]
    }


# --- Result shape handling ------------------------------------------------


@pytest.mark.asyncio
async def test_fallback_result_without_content_attribute_is_returned_as_is() -> None:
    """Some fallback handlers return raw content directly. The function
    must return it unchanged when no .content attribute is present."""
    raw_result = TextContent(type="text", text="bare")
    fallback = AsyncMock(return_value=raw_result)

    ctx = _make_ctx(
        sample_raises=Exception("Client does not support sampling"),
        fallback_handler=fallback,
    )

    result = await sample_with_fallback(ctx, "ping")
    assert result is raw_result


# --- Custom params --------------------------------------------------------


@pytest.mark.asyncio
async def test_custom_max_tokens_propagates_to_client() -> None:
    """Caller-supplied max_tokens reaches ctx.sample (happy path)."""
    expected = TextContent(type="text", text="ok")
    ctx = _make_ctx(sample_result=expected)

    await sample_with_fallback(ctx, "ping", max_tokens=2048)

    ctx.sample.assert_awaited_once()
    kwargs = ctx.sample.await_args.kwargs
    assert kwargs["max_tokens"] == 2048


@pytest.mark.asyncio
async def test_default_max_tokens_is_512_when_omitted() -> None:
    """When no max_tokens is passed, the documented default is 512."""
    expected = TextContent(type="text", text="ok")
    ctx = _make_ctx(sample_result=expected)

    await sample_with_fallback(ctx, "ping")

    kwargs = ctx.sample.await_args.kwargs
    assert kwargs["max_tokens"] == 512
