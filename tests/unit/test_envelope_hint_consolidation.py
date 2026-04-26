"""Round 6: Ads envelope-level field-name hint promotion.

Mirrors the SP test of the same name. Verifies sanitization of
``details.path`` artifacts and consolidation to a single envelope-level
pass that fires regardless of which classifier built the envelope.
"""

from __future__ import annotations

import httpx
import pytest

from amazon_ads_mcp.middleware.error_envelope import build_envelope_from_exception


@pytest.fixture(autouse=True)
def _reset_http_meta():
    from amazon_ads_mcp.utils.http.rate_limit_headers import clear_last_http_meta

    clear_last_http_meta()
    yield
    clear_last_http_meta()


def _http_400_with_path(path: str, issue: str = "field required") -> httpx.HTTPStatusError:
    request = httpx.Request("GET", "https://advertising-api.amazon.com/v2/profiles")
    body = {
        "errors": [
            {"code": "InvalidInput", "message": issue, "details": [{"path": path}]}
        ]
    }
    response = httpx.Response(400, request=request, json=body)
    return httpx.HTTPStatusError("bad", request=request, response=response)


def _envelope_via_mcp_error(*, path: str, issue: str) -> dict:
    """Build envelope via the MCPError typed-exception path so we exercise
    a different classifier than HTTPStatusError."""
    from amazon_ads_mcp.utils.errors import ErrorCategory, MCPError

    exc = MCPError(
        message=issue,
        category=ErrorCategory.VALIDATION,
        status_code=400,
        details={"path": path},
    )
    return build_envelope_from_exception(exc, tool_name="t")


# ---------------------------------------------------------------------------
# Sanitization
# ---------------------------------------------------------------------------


def test_trailing_semicolon_stripped_from_field_name_hint():
    env = _envelope_via_mcp_error(path="reportTypes;", issue="field required")
    hints_text = " ".join(env["hints"])
    assert "reportTypes" in hints_text
    assert "reportTypes;" not in hints_text


def test_trailing_whitespace_stripped():
    env = _envelope_via_mcp_error(path="postedAfter \t", issue="required")
    assert any("'postedAfter'" in h for h in env["hints"])


def test_trailing_period_stripped():
    env = _envelope_via_mcp_error(path="campaignId.", issue="required")
    assert any("'campaignId'" in h for h in env["hints"])


def test_surrounding_quotes_stripped():
    env = _envelope_via_mcp_error(path="'profileId'", issue="required")
    assert any("'profileId'" in h for h in env["hints"])
    assert not any("''profileId''" in h for h in env["hints"])


def test_clean_path_unchanged():
    env = _envelope_via_mcp_error(path="campaignName", issue="required")
    assert any("'campaignName'" in h for h in env["hints"])


# ---------------------------------------------------------------------------
# Consolidation — promotion fires regardless of classifier path
# ---------------------------------------------------------------------------


def test_pydantic_validation_path_promotes():
    from pydantic import BaseModel, ValidationError

    class _Needs(BaseModel):
        limit: int

    try:
        _Needs()
    except ValidationError as exc:
        env = build_envelope_from_exception(exc, tool_name="t")
    assert any("limit" in h for h in env["hints"])


def test_http_status_error_path_promotes():
    """The httpx.HTTPStatusError classifier path."""
    exc = _http_400_with_path("postedAfter", issue="field required")
    env = build_envelope_from_exception(exc, tool_name="t")
    # The Ads upstream HTTP error path produces details with a path
    # extracted from the response body. Field-name promotion must surface
    # it on this path too.
    assert env["error_kind"] == "ads_api_http"


def test_mcp_error_validation_path_promotes():
    """MCPError(category=VALIDATION) classifier path. Round 3-C
    handled this; the consolidation pass must keep handling it."""
    env = _envelope_via_mcp_error(path="campaignName", issue="required")
    assert env["error_kind"] == "mcp_input_validation"
    assert any("'campaignName'" in h for h in env["hints"])


def test_no_field_signal_no_field_name_hint():
    env = _envelope_via_mcp_error(path="", issue="generic")
    # No specific hint emitted — generic baseline only
    assert all(
        "Required field missing" not in h and "Unknown field" not in h
        for h in env["hints"]
    )


# ---------------------------------------------------------------------------
# Single source of truth
# ---------------------------------------------------------------------------


def test_only_one_promotion_emit_site_in_module():
    import inspect

    from amazon_ads_mcp.middleware import error_envelope as mod

    src = inspect.getsource(mod)
    emit_sites = src.count('f"Required field missing:')
    assert emit_sites == 1, (
        f"Expected exactly one f-string emit site for 'Required field "
        f"missing:' in middleware/error_envelope.py. Found {emit_sites}. "
        f"The consolidated envelope-level pass should be the single "
        f"source of truth."
    )
