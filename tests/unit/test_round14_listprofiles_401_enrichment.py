"""Round 14 hotfix (Gap 3): listProfiles 401 envelope enrichment.

Two regressions pinned:

1. Upstream Amazon Ads error body structure (``code``, ``message``,
   ``requestId``, headers like ``x-amzn-RequestId``) must surface in
   ``details[0]`` under documented keys — agents shouldn't have to
   parse a stringified ``issue`` to distinguish (a) bearer expired,
   (b) missing endpoint scope, (c) profile-scope header missing.

2. ``*listProfiles*`` 401/403 envelopes carry a tool-aware hint that
   redirects v1-report flows to ``allv1_QueryAdvertiserAccount`` (which
   doesn't require Profiles scope) and warns that a 401 here usually
   means missing endpoint scope, not expired credentials.

Boundary tests pin no-false-positives: non-401 statuses, non-Profiles
tool names, and non-dict bodies must not regress.
"""

from __future__ import annotations

import httpx

from amazon_ads_mcp.middleware.error_envelope import (
    build_envelope_from_exception,
)


def _make_http_error(
    *,
    status: int = 401,
    body_dict: dict | None = None,
    body_text: str | None = None,
    headers: dict[str, str] | None = None,
) -> httpx.HTTPStatusError:
    """Build a minimal HTTPStatusError shaped like an Amazon Ads upstream."""
    import json as _json

    request = httpx.Request("GET", "https://advertising-api.amazon.com/v2/profiles")
    if body_dict is not None:
        content = _json.dumps(body_dict).encode("utf-8")
        hdr = {"content-type": "application/json"}
    else:
        content = (body_text or "").encode("utf-8")
        hdr = {}
    if headers:
        hdr.update(headers)
    response = httpx.Response(
        status_code=status,
        content=content,
        request=request,
        headers=hdr,
    )
    return httpx.HTTPStatusError("upstream", request=request, response=response)


# ---- Pass-through enrichment of upstream body ----


def test_401_dict_body_surfaces_upstream_code_message_requestid() -> None:
    """A 401 with a structured Amazon Ads error body should populate
    ``details[0].upstream_code``, ``upstream_message``, and
    ``request_id`` so agents can branch on the upstream cause."""
    exc = _make_http_error(
        status=401,
        body_dict={
            "code": "UNAUTHORIZED",
            "message": "Access token has insufficient scope.",
            "requestId": "abc-123-def",
            "details": [{"reason": "missing_scope:advertising::list_profiles"}],
        },
    )
    envelope = build_envelope_from_exception(
        exc, tool_name="ac_listProfiles", tool_args=None, normalized=None
    )
    assert envelope["error_code"] == "ADS_API_HTTP_401"
    detail = envelope["details"][0]
    assert detail["upstream_code"] == "UNAUTHORIZED"
    assert detail["upstream_message"] == "Access token has insufficient scope."
    assert detail["request_id"] == "abc-123-def"
    assert detail["upstream_details"]  # nested details preserved
    # Backwards-compat: canonical triplet still present.
    assert detail["path"] == ""
    assert detail["received_type"] == "dict"
    assert "issue" in detail


def test_401_response_header_request_id_used_when_body_lacks_one() -> None:
    """When the upstream body has no requestId, the response header
    (Amazon's standard ``x-amzn-RequestId``) should fill the gap."""
    exc = _make_http_error(
        status=401,
        body_dict={"code": "UNAUTHORIZED", "message": "Nope."},
        headers={"x-amzn-RequestId": "header-rid-789"},
    )
    envelope = build_envelope_from_exception(
        exc, tool_name="ac_listProfiles", tool_args=None, normalized=None
    )
    assert envelope["details"][0]["request_id"] == "header-rid-789"


def test_non_dict_body_keeps_request_id_when_header_present() -> None:
    """Plain-text upstream bodies still benefit from the header-derived
    request_id so support escalations have something to correlate."""
    exc = _make_http_error(
        status=503,
        body_text="Service Unavailable",
        headers={"x-amzn-RequestId": "header-rid-text"},
    )
    envelope = build_envelope_from_exception(
        exc, tool_name="some_tool", tool_args=None, normalized=None
    )
    assert envelope["details"][0]["request_id"] == "header-rid-text"
    assert envelope["details"][0]["received_type"] == "str"


def test_dict_body_without_structured_fields_no_extra_keys() -> None:
    """A dict body with no recognizable code/message/requestId fields
    shouldn't synthesize empty enrichment keys — agents that look for
    those keys should rely on presence as signal."""
    exc = _make_http_error(
        status=400,
        body_dict={"weirdField": "weirdValue"},
    )
    envelope = build_envelope_from_exception(
        exc, tool_name="some_tool", tool_args=None, normalized=None
    )
    detail = envelope["details"][0]
    assert "upstream_code" not in detail
    assert "upstream_message" not in detail
    assert "request_id" not in detail


# ---- Tool-aware listProfiles hint ----


def test_listprofiles_401_carries_v1_redirect_hint() -> None:
    """``ac_listProfiles`` 401 should steer v1-report flows toward
    ``allv1_QueryAdvertiserAccount`` and flag scope (not credentials)
    as the likely cause."""
    exc = _make_http_error(
        status=401,
        body_dict={"code": "UNAUTHORIZED", "message": "scope missing"},
    )
    envelope = build_envelope_from_exception(
        exc, tool_name="ac_listProfiles", tool_args=None, normalized=None
    )
    hints_text = " ".join(envelope.get("hints") or [])
    assert "allv1_QueryAdvertiserAccount" in hints_text
    assert "Profiles" in hints_text
    assert "scope" in hints_text


def test_listprofiles_403_also_carries_hint() -> None:
    """403 has the same operational meaning as 401 for this endpoint
    (missing scope, not invalid credentials), so the hint applies."""
    exc = _make_http_error(
        status=403,
        body_dict={"code": "FORBIDDEN", "message": "no"},
    )
    envelope = build_envelope_from_exception(
        exc, tool_name="AccountsProfiles_listProfiles", tool_args=None, normalized=None
    )
    hints_text = " ".join(envelope.get("hints") or [])
    assert "allv1_QueryAdvertiserAccount" in hints_text


def test_listprofiles_500_does_not_carry_redirect_hint() -> None:
    """5xx is an upstream-side issue, not a scope/identity problem —
    the v1-redirect hint would be misleading."""
    exc = _make_http_error(
        status=500,
        body_dict={"code": "INTERNAL_ERROR", "message": "oops"},
    )
    envelope = build_envelope_from_exception(
        exc, tool_name="ac_listProfiles", tool_args=None, normalized=None
    )
    hints_text = " ".join(envelope.get("hints") or [])
    assert "allv1_QueryAdvertiserAccount" not in hints_text


def test_non_listprofiles_401_does_not_carry_redirect_hint() -> None:
    """A 401 from a different endpoint shouldn't carry listProfiles-
    specific guidance — the redirect would be wrong context."""
    exc = _make_http_error(
        status=401,
        body_dict={"code": "UNAUTHORIZED", "message": "no"},
    )
    envelope = build_envelope_from_exception(
        exc, tool_name="dsp_listOrders", tool_args=None, normalized=None
    )
    hints_text = " ".join(envelope.get("hints") or [])
    assert "allv1_QueryAdvertiserAccount" not in hints_text


def test_listprofiles_hint_appears_before_generic_inspect_hint() -> None:
    """Tool-aware guidance should be FIRST in the hints[] list so
    agents read it before the generic 'inspect details' boilerplate."""
    exc = _make_http_error(
        status=401,
        body_dict={"code": "UNAUTHORIZED", "message": "scope"},
    )
    envelope = build_envelope_from_exception(
        exc, tool_name="ac_listProfiles", tool_args=None, normalized=None
    )
    hints = envelope.get("hints") or []
    assert hints, "expected at least one hint"
    # First hint mentions the v1 redirect; later hints can be generic.
    assert "allv1_QueryAdvertiserAccount" in hints[0]


def test_unknown_tool_name_does_not_blow_up() -> None:
    """Defensive: ``tool_name=None`` must not crash the enrichment."""
    exc = _make_http_error(
        status=401, body_dict={"code": "UNAUTHORIZED", "message": "no"}
    )
    envelope = build_envelope_from_exception(
        exc, tool_name=None, tool_args=None, normalized=None
    )
    # Generic hint is fine; just shouldn't carry the listProfiles hint
    # or raise.
    hints_text = " ".join(envelope.get("hints") or [])
    assert "allv1_QueryAdvertiserAccount" not in hints_text
