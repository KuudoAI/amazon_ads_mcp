"""End-to-end smoke for envelope classification of input-validation errors
(Commit 4 of fix/mcp-surface-quality).

Verifies that input-validation errors raised inside tool implementations
surface through the FastMCP wire as classified errors (not opaque internal
errors). Targets two real bug paths:

1. report_fields wrapper re-raising ReportFieldsToolError as bare ValueError
   → classified as internal_error in envelope. Fix: re-raise as typed
   ValidationError → classified as mcp_input_validation.
2. set_active_identity tool re-raising auth_manager's ValueError unchanged
   → same misclassification. Fix: catch ValueError and re-raise as typed
   ValidationError.

Both fixes verified end-to-end by capturing the ToolError surfaced through
the FastMCP Client and asserting on its content shape.
"""

from __future__ import annotations

import pathlib
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio

pytest.importorskip("fastmcp")


def _resources_present() -> bool:
    root = pathlib.Path(__file__).parents[2]
    return (root / "openapi" / "resources").exists() or (
        root / "dist" / "openapi" / "resources"
    ).exists()


@pytest_asyncio.fixture
async def mcp_server():
    if not _resources_present():
        pytest.skip("No openapi/resources or dist/openapi/resources present")

    from amazon_ads_mcp.server.mcp_server import create_amazon_ads_server

    return await create_amazon_ads_server()


# ---------------------------------------------------------------------------
# report_fields — ReportFieldsToolError surfaces as input-validation error
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_report_fields_invalid_mode_args_surfaces_as_validation_error(
    mcp_server,
):
    """`mode='validate'` without `validate_fields` triggers a real
    ReportFieldsToolError(INVALID_MODE_ARGS) raise site
    (report_fields_v1_handler.py:188). Wrapper must re-raise as typed
    ValidationError so the envelope translator classifies as
    mcp_input_validation, NOT internal_error."""
    from fastmcp import Client
    from fastmcp.exceptions import ToolError

    async with Client(mcp_server) as client:
        with pytest.raises(ToolError) as excinfo:
            # mode='validate' but no validate_fields → INVALID_MODE_ARGS
            await client.call_tool("report_fields", {"mode": "validate"})

    msg = str(excinfo.value)
    # The error code is preserved in the ValidationError details and shows
    # up in the surfaced message; should also reference what's missing.
    assert "validate_fields" in msg or "INVALID_MODE_ARGS" in msg, (
        f"expected validate_fields/INVALID_MODE_ARGS reason in error, got {msg!r}"
    )


@pytest.mark.asyncio
async def test_report_fields_pydantic_literal_validation_still_works(mcp_server):
    """Regression smoke: `mode='garbage'` hits Pydantic Literal validation
    upstream of the wrapper. Confirm it still surfaces as a clear validation
    error after the wrapper change — the wrapper fix must not break the
    pre-existing Pydantic-validated path."""
    from fastmcp import Client
    from fastmcp.exceptions import ToolError

    async with Client(mcp_server) as client:
        with pytest.raises(ToolError) as excinfo:
            await client.call_tool("report_fields", {"mode": "garbage"})

    msg = str(excinfo.value).lower()
    # Pydantic mentions the Literal options or the offending value
    assert "garbage" in msg or "literal" in msg or "validation" in msg, (
        f"expected pydantic validation reason in error, got {excinfo.value!r}"
    )


# ---------------------------------------------------------------------------
# set_active_identity — auth_manager ValueError surfaces as validation error
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_set_active_identity_unknown_id_surfaces_as_validation_error(
    monkeypatch, mcp_server
):
    """auth_manager.set_active_identity raises ValueError("Identity X not
    found") for unknown IDs. Tool layer must re-raise as typed
    ValidationError so the envelope classifies as mcp_input_validation,
    not internal_error.

    The ``set_active_identity`` MCP tool only registers under the
    OpenBridge auth provider (see builtin_tools.py:1631). When the test
    env uses the direct provider, the MCP-protocol path can't be
    exercised — exercise the underlying _set_active_identity_impl
    directly to still cover the production code path. The unit test
    in test_envelope_classification.py covers the typed-error translation
    in tools/identity.py.
    """
    from fastmcp import Client

    from amazon_ads_mcp.tools import identity as identity_tools

    # Patch get_auth_manager to return a manager whose set_active_identity
    # raises the same ValueError the real auth_manager would for unknown IDs.
    auth_manager_mock = AsyncMock()
    auth_manager_mock.set_active_identity = AsyncMock(
        side_effect=ValueError("Identity 99999999 not found")
    )
    monkeypatch.setattr(
        identity_tools, "get_auth_manager", lambda: auth_manager_mock
    )

    async with Client(mcp_server) as client:
        tool_names = {t.name for t in await client.list_tools()}

    if "set_active_identity" in tool_names:
        # OpenBridge env: full MCP-protocol path
        from fastmcp.exceptions import ToolError

        async with Client(mcp_server) as client:
            with pytest.raises(ToolError) as excinfo:
                await client.call_tool(
                    "set_active_identity", {"identity_id": "99999999"}
                )
        msg = str(excinfo.value)
    else:
        # Direct env: exercise the underlying impl path directly. Still
        # production code (tools/identity.py + the typed-error translation
        # we just added). Unit test in test_envelope_classification.py also
        # covers this isolated.
        from amazon_ads_mcp.utils.errors import ErrorCategory, ValidationError

        with pytest.raises(ValidationError) as excinfo:
            from amazon_ads_mcp.tools.identity import (
                SetActiveIdentityRequest,
                set_active_identity,
            )

            await set_active_identity(
                SetActiveIdentityRequest(identity_id="99999999")
            )
        assert excinfo.value.category == ErrorCategory.VALIDATION
        msg = str(excinfo.value)
        assert excinfo.value.details.get("error_code") == "IDENTITY_NOT_FOUND"

    assert "99999999" in msg, (
        f"expected identity ID in error message, got {msg!r}"
    )
    assert "not found" in msg.lower(), (
        f"expected 'not found' in validation error, got {msg!r}"
    )
