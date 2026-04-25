"""Verify envelope and schema-normalization middleware are registered in the
correct order in ``server_builder``.

Per the v1 contract (openbridge-mcp/CONTRACT.md):

  envelope translator (outermost)
    → schema-normalization
      → existing guardrails (create_report_guardrail, etc.)
        → tool dispatch (innermost)

In FastMCP, middleware appended **first** runs **outermost** for ``on_call_tool``.
So the test checks that the envelope middleware appears at index 0 and the
schema-normalization middleware appears immediately after.
"""

from __future__ import annotations

import pytest


def _make_builder_with_mocks():
    """Construct a ServerBuilder, then patch auth_manager + server to the
    minimal shape ``_setup_middleware`` reads, so we can call it in
    isolation without booting OpenBridge auth, OAuth, etc.
    """
    from types import SimpleNamespace

    from fastmcp import FastMCP

    from amazon_ads_mcp.server.server_builder import ServerBuilder

    builder = ServerBuilder()
    # Minimal auth_manager: provider_type "direct" skips the OpenBridge path
    # and the OAuth path is gated by env vars (off in CI).
    builder.auth_manager = SimpleNamespace(provider=SimpleNamespace(provider_type="direct"))
    builder.server = FastMCP("test-ordering")
    return builder


@pytest.mark.asyncio
async def test_envelope_middleware_runs_before_error_handling_and_normalization():
    """The v1 envelope translator must run outermost among the middleware
    we register, i.e. before FastMCP's ``ErrorHandlingMiddleware`` and the
    schema-normalization layer.

    FastMCP installs its own default middleware (e.g. ``DereferenceRefsMiddleware``)
    at index 0 before user code runs; we don't reorder those. The contract
    is about *our* tool-call error path being the outermost user-added wrapper.
    """
    from fastmcp.server.middleware.error_handling import ErrorHandlingMiddleware

    from amazon_ads_mcp.middleware.error_envelope_middleware import (
        ErrorEnvelopeMiddleware,
    )
    from amazon_ads_mcp.middleware.schema_normalization import (
        SchemaKeyNormalizationMiddleware,
    )

    builder = _make_builder_with_mocks()
    await builder._setup_middleware()

    types = [type(m).__name__ for m in builder.server.middleware]
    envelope_idx = next(
        (i for i, m in enumerate(builder.server.middleware) if isinstance(m, ErrorEnvelopeMiddleware)),
        None,
    )
    error_handling_idx = next(
        (i for i, m in enumerate(builder.server.middleware) if isinstance(m, ErrorHandlingMiddleware)),
        None,
    )
    norm_idx = next(
        (
            i
            for i, m in enumerate(builder.server.middleware)
            if isinstance(m, SchemaKeyNormalizationMiddleware)
        ),
        None,
    )

    assert envelope_idx is not None, f"ErrorEnvelopeMiddleware not registered. chain: {types}"
    assert norm_idx is not None, f"SchemaKeyNormalizationMiddleware not registered. chain: {types}"
    assert error_handling_idx is not None, f"ErrorHandlingMiddleware not registered. chain: {types}"

    assert envelope_idx < norm_idx < error_handling_idx, (
        f"required order: envelope ({envelope_idx}) < "
        f"normalization ({norm_idx}) < error_handling ({error_handling_idx}). "
        f"chain: {types}"
    )


@pytest.mark.asyncio
async def test_meta_injection_runs_after_normalization_before_error_handling():
    """``MetaInjectionMiddleware`` (Phase 3) must sit inside both the
    envelope wrapper and schema-normalization, but outside FastMCP's
    ErrorHandlingMiddleware so it only sees the success path."""
    from fastmcp.server.middleware.error_handling import ErrorHandlingMiddleware

    from amazon_ads_mcp.middleware.error_envelope_middleware import (
        ErrorEnvelopeMiddleware,
    )
    from amazon_ads_mcp.middleware.meta_injection_middleware import (
        MetaInjectionMiddleware,
    )
    from amazon_ads_mcp.middleware.schema_normalization import (
        SchemaKeyNormalizationMiddleware,
    )

    builder = _make_builder_with_mocks()
    await builder._setup_middleware()

    types = [type(m).__name__ for m in builder.server.middleware]

    def _idx_of(cls):
        return next(
            (i for i, m in enumerate(builder.server.middleware) if isinstance(m, cls)),
            None,
        )

    envelope_idx = _idx_of(ErrorEnvelopeMiddleware)
    norm_idx = _idx_of(SchemaKeyNormalizationMiddleware)
    meta_idx = _idx_of(MetaInjectionMiddleware)
    error_handling_idx = _idx_of(ErrorHandlingMiddleware)

    assert envelope_idx is not None and norm_idx is not None
    assert meta_idx is not None, f"MetaInjectionMiddleware not registered. chain: {types}"
    assert error_handling_idx is not None

    assert envelope_idx < norm_idx < meta_idx < error_handling_idx, (
        f"required order: envelope ({envelope_idx}) < "
        f"normalization ({norm_idx}) < meta_injection ({meta_idx}) < "
        f"error_handling ({error_handling_idx}). chain: {types}"
    )
