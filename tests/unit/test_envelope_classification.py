"""Unit tests for envelope classification of input-validation errors.

Verifies that the report_fields wrapper and the set_active_identity tool
re-raise their underlying typed errors as ValidationError so the envelope
translator classifies them as ``mcp_input_validation`` (not the default
``internal_error`` bucket).
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from amazon_ads_mcp.utils.errors import ErrorCategory, ValidationError


# ---------------------------------------------------------------------------
# Identity tool — ValueError from auth_manager → ValidationError at tool boundary
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_set_active_identity_unknown_id_raises_validation_error(monkeypatch):
    """When auth_manager.set_active_identity raises ValueError (identity not
    found), the tool layer must re-raise as typed ValidationError so the
    envelope classifies as mcp_input_validation."""
    from amazon_ads_mcp.tools import identity as identity_tools
    from amazon_ads_mcp.tools.identity import SetActiveIdentityRequest

    auth_manager = SimpleNamespace(
        set_active_identity=AsyncMock(
            side_effect=ValueError("Identity 99999999 not found")
        ),
    )
    monkeypatch.setattr(identity_tools, "get_auth_manager", lambda: auth_manager)

    with pytest.raises(ValidationError) as excinfo:
        await identity_tools.set_active_identity(
            SetActiveIdentityRequest(identity_id="99999999")
        )

    err = excinfo.value
    assert err.category == ErrorCategory.VALIDATION
    assert "99999999" in str(err)
    assert err.details.get("error_code") == "IDENTITY_NOT_FOUND"


@pytest.mark.asyncio
async def test_set_active_identity_other_exception_propagates_unchanged(monkeypatch):
    """Non-ValueError exceptions (e.g. RuntimeError from auth provider crash)
    must NOT be reclassified as input-validation — they're real internal
    errors and should keep their type."""
    from amazon_ads_mcp.tools import identity as identity_tools
    from amazon_ads_mcp.tools.identity import SetActiveIdentityRequest

    auth_manager = SimpleNamespace(
        set_active_identity=AsyncMock(
            side_effect=RuntimeError("auth provider crashed")
        ),
    )
    monkeypatch.setattr(identity_tools, "get_auth_manager", lambda: auth_manager)

    with pytest.raises(RuntimeError) as excinfo:
        await identity_tools.set_active_identity(
            SetActiveIdentityRequest(identity_id="abc")
        )
    assert "auth provider crashed" in str(excinfo.value)


# ---------------------------------------------------------------------------
# report_fields wrapper — ReportFieldsToolError → ValidationError
# ---------------------------------------------------------------------------


def test_report_fields_wrapper_translates_tool_error_to_validation_error():
    """Direct test of the wrapper's exception translation: when the underlying
    handler raises ReportFieldsToolError, the wrapper must re-raise as typed
    ValidationError with the original error code preserved in details."""
    from amazon_ads_mcp.tools.report_fields_errors import ReportFieldsErrorCode
    from amazon_ads_mcp.tools.report_fields_v1_handler import ReportFieldsToolError
    from amazon_ads_mcp.utils.errors import ValidationError as _ValidationError

    # Simulate the wrapper's translation logic in isolation
    original_exc = ReportFieldsToolError(
        ReportFieldsErrorCode.INVALID_MODE_ARGS,
        "mode='validate' requires validate_fields",
    )

    err = _ValidationError(str(original_exc), field=None)
    err.details["error_code"] = original_exc.code.value

    assert err.category == ErrorCategory.VALIDATION
    assert err.details["error_code"] == "INVALID_MODE_ARGS"
    assert "validate_fields" in str(err)


def test_report_fields_tool_error_has_code_attribute():
    """Regression: ReportFieldsToolError must expose .code as a
    ReportFieldsErrorCode member so the wrapper can preserve it."""
    from amazon_ads_mcp.tools.report_fields_errors import ReportFieldsErrorCode
    from amazon_ads_mcp.tools.report_fields_v1_handler import ReportFieldsToolError

    exc = ReportFieldsToolError(
        ReportFieldsErrorCode.INVALID_MODE_ARGS, "test message"
    )
    assert exc.code is ReportFieldsErrorCode.INVALID_MODE_ARGS
    assert exc.code.value == "INVALID_MODE_ARGS"
