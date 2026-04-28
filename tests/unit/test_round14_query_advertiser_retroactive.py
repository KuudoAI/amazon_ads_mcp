"""Round 14 Phase A — retroactive-validate gate widened to QueryAdvertiserAccount.

Low-impact hardening (NOT a primary user-visible win): normal QAA
calls don't carry ``query.fields[]``, so ``_enrich_with_catalog_validate``
no-ops most of the time. The widen exists to catch the rare
pathological case where an agent constructs a hybrid CreateReport-style
body by mistake — and to keep the gate symmetric with the broader
"v1↔v3 reflexes get catalog enrichment regardless of failing endpoint"
intent.

Two regressions pinned:

  1. **No false-positive**: a normal QAA 4xx (no query.fields[] in
     args) MUST NOT receive catalog enrichment hints.
  2. **Pathological hybrid body**: when an agent passes
     ``{"reports": [{"query": {"fields": ["metric.cost"]}}]}`` to
     QueryAdvertiserAccount by mistake, the upstream rejects but
     the envelope SHOULD include catalog suggestions
     (``metric.cost → metric.totalCost``) so the agent is steered
     toward the correct endpoint.
"""

from __future__ import annotations

import httpx

from amazon_ads_mcp.middleware.error_envelope import (
    build_envelope_from_exception,
)


def _make_http_error(status: int = 400, body: str = "Bad Request") -> httpx.HTTPStatusError:
    """Reused from test_catalog_aware_hints helper pattern."""
    request = httpx.Request(
        "POST",
        "https://advertising-api.amazon.com/adsAccounts/list",
    )
    response = httpx.Response(
        status_code=status,
        content=body.encode("utf-8"),
        request=request,
    )
    return httpx.HTTPStatusError("Bad Request", request=request, response=response)


def test_query_advertiser_normal_args_no_catalog_enrichment() -> None:
    """Normal QAA call args (no ``query.fields[]``) must NOT trigger
    catalog enrichment — `_enrich_with_catalog_validate` walks for
    that path and returns silently when absent. Confirms no false-
    positive hint emission for the common case."""
    exc = _make_http_error()
    tool_args = {
        "advertiserAccountIdFilter": ["amzn1.ads-account.g.placeholder"],
        "isGlobalAccountFilter": False,
    }
    envelope = build_envelope_from_exception(
        exc,
        tool_name="allv1_QueryAdvertiserAccount",
        tool_args=tool_args,
    )
    hints = envelope.get("hints") or []
    joined = " ".join(hints)
    # No catalog clause should fire — args don't have query.fields[].
    assert "v1 catalog" not in joined, (
        f"normal QAA args must NOT trigger catalog enrichment; "
        f"got hints: {hints}"
    )
    # Pre-flight 'report_fields(mode=\"validate\", ...)' guidance is
    # also catalog-validate-only — should not fire.
    assert "report_fields" not in joined or "validate" not in joined


def test_query_advertiser_hybrid_body_triggers_catalog_enrichment() -> None:
    """Pathological case: agent passes a CreateReport-shaped body to
    QueryAdvertiserAccount. The widened gate now picks this up so the
    catalog-driven suggestions steer the agent toward the right
    endpoint (and the right field names)."""
    exc = _make_http_error()
    tool_args = {
        "reports": [
            {
                "query": {"fields": ["metric.cost", "campaign.id"]},
            }
        ],
    }
    envelope = build_envelope_from_exception(
        exc,
        tool_name="allv1_QueryAdvertiserAccount",
        tool_args=tool_args,
    )
    hints = envelope.get("hints") or []
    joined = " ".join(hints)
    assert "v1 catalog" in joined, (
        f"hybrid CreateReport-style body should trigger catalog "
        f"enrichment via the widened QAA gate; got: {hints}"
    )
    assert "metric.cost" in joined
    assert "metric.totalCost" in joined
