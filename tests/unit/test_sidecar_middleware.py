"""Unit tests for SidecarTransformMiddleware — the real fix for Issue 6.

Pins the behavior the legacy sidecar_loader path silently skipped:
- `reportId` (singular) must be rewritten to `reportIds=[...]` BEFORE the
  tool's schema validation runs.
- Tools without a matching rule pass through untouched.
- A malformed rule must not break the call path.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any, Awaitable, Callable

import pytest

from amazon_ads_mcp.server.sidecar_middleware import SidecarTransformMiddleware

REPO_ROOT = Path(__file__).resolve().parents[2]
RESOURCES_DIR = REPO_ROOT / "openapi" / "resources"
OVERLAYS_DIR = REPO_ROOT / "openapi" / "overlays"


def _middleware() -> SidecarTransformMiddleware:
    """Construct middleware with both base + overlay sources.

    The base transform files under openapi/resources/ are gitignored and
    may or may not be present in a fresh checkout. Overlays under
    openapi/overlays/ are source-controlled and always present — they're
    the authoritative source for alias rules (survive the private
    .build/ regen).
    """
    return SidecarTransformMiddleware(RESOURCES_DIR, overlays_dir=OVERLAYS_DIR)


def _make_context(tool_name: str, arguments: dict[str, Any]) -> SimpleNamespace:
    """Build a minimal MiddlewareContext-compatible object.

    The middleware only reads ``context.message.name`` and
    ``context.message.arguments``; we don't need the real MCP types here.
    """
    message = SimpleNamespace(name=tool_name, arguments=arguments)
    return SimpleNamespace(message=message)


async def _call_next_capture(captured: list) -> Callable[..., Awaitable[Any]]:
    async def _call_next(ctx):
        captured.append(dict(ctx.message.arguments or {}))
        return "ok"

    return _call_next


@pytest.mark.asyncio
async def test_alias_rewrites_report_id_to_report_ids_list():
    middleware = _middleware()
    ctx = _make_context(
        "allv1_AdsApiv1RetrieveReport",
        {"reportId": "singular-abc-123"},
    )

    captured: list[dict] = []

    async def call_next(c):
        captured.append(dict(c.message.arguments))
        return "ok"

    result = await middleware.on_call_tool(ctx, call_next)
    assert result == "ok"
    assert captured, "call_next was never invoked"
    rewritten = captured[0]
    # Canonical plural form must be populated; the executor's arg_aliases
    # is additive (doesn't delete the original singular), which is safe —
    # downstream HTTP clients ignore unknown params.
    assert rewritten.get("reportIds") == ["singular-abc-123"], rewritten


@pytest.mark.asyncio
async def test_alias_does_not_overwrite_existing_plural_form():
    middleware = _middleware()
    ctx = _make_context(
        "allv1_AdsApiv1RetrieveReport",
        {"reportIds": ["plural-stays"]},
    )

    captured: list[dict] = []

    async def call_next(c):
        captured.append(dict(c.message.arguments))
        return "ok"

    await middleware.on_call_tool(ctx, call_next)
    assert captured[0].get("reportIds") == ["plural-stays"]


@pytest.mark.asyncio
async def test_tool_without_rule_passes_through():
    middleware = _middleware()
    ctx = _make_context("nonexistent_tool", {"a": 1, "b": 2})

    captured: list[dict] = []

    async def call_next(c):
        captured.append(dict(c.message.arguments))
        return "ok"

    await middleware.on_call_tool(ctx, call_next)
    assert captured[0] == {"a": 1, "b": 2}


@pytest.mark.asyncio
async def test_middleware_stats_count_loaded_rules():
    middleware = _middleware()
    stats = middleware.stats()
    # We know at least the reportId alias rule loaded — it lives in
    # openapi/overlays/AdsAPIv1All.json (source-controlled, present on
    # every checkout). Base resources under openapi/resources/ are
    # gitignored and may be entirely absent on a fresh CI checkout, in
    # which case `rules` is 0 and every compiled transform comes from
    # an overlay. Sum both raw counters for the invariant.
    assert stats["compiled_transforms"] >= 1
    assert stats["tools_with_transforms"] >= 1
    assert stats["rules"] + stats["overlays"] >= stats["compiled_transforms"]


@pytest.mark.asyncio
async def test_missing_resources_dir_yields_empty_middleware(tmp_path):
    """Constructing against an empty/missing dir must not blow up."""
    middleware = SidecarTransformMiddleware(tmp_path / "does-not-exist")
    stats = middleware.stats()
    assert stats["compiled_transforms"] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "tool_name,singular_key,plural_key",
    [
        # Prefixed form (MCP protocol path).
        ("allv1_AdsApiv1RetrieveReport", "reportId", "reportIds"),
        ("beta_AdsApiv1RetrieveReport", "reportId", "reportIds"),
        ("allv1_AdsApiv1DeleteReport", "reportId", "reportIds"),
        ("beta_AdsApiv1DeleteReport", "reportId", "reportIds"),
        # Un-prefixed form (Code Mode sandbox path — observed in the
        # production traceback at fastmcp/experimental/transforms/
        # code_mode.py:134 where MontySandbox dispatches via
        # operationId directly, not the MCP-prefixed name).
        ("AdsApiv1RetrieveReport", "reportId", "reportIds"),
        ("AdsApiv1DeleteReport", "reportId", "reportIds"),
        # NOTE: DSPRetrieveCommitmentSpend is intentionally NOT tested
        # here. Its request body is an array of OBJECTS
        # ([{commitmentId, spendDimension}]), not scalars. A wrap:list
        # alias leaves spendDimension floating at the top level and
        # triggers Amazon's cryptic "Expected null" — worse than the
        # "field required" the caller would otherwise see. Overlay rule
        # for it is intentionally absent; see openapi/overlays/AdsAPIv1All.json
        # for the rationale.
    ],
)
async def test_singular_aliases_rewrite_on_both_prefixed_and_unprefixed(
    tool_name, singular_key, plural_key
):
    """Alias must fire on BOTH surfaces:
      * MCP protocol path → prefixed name (e.g. ``allv1_AdsApiv1RetrieveReport``)
      * Code Mode sandbox → un-prefixed operationId (``AdsApiv1RetrieveReport``)

    Earlier versions registered under the prefixed form only; the sandbox
    path silently missed the rewrite. Production symptom: HTTP 400 from
    Amazon because the call reached the API without ``reportIds``."""
    middleware = _middleware()
    rewritten = await middleware.rewrite_args(tool_name, {singular_key: "abc"})
    assert rewritten.get(plural_key) == ["abc"], (
        f"{tool_name}: singular {singular_key!r} did not rewrite to "
        f"{plural_key!r}; got {rewritten!r}"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "tool_name",
    [
        "allv1_DSPRetrieveCommitmentSpend",
        "DSPRetrieveCommitmentSpend",
    ],
)
async def test_dsp_commitment_spend_intentionally_not_aliased(tool_name):
    """Guard against someone re-adding the DSPRetrieveCommitmentSpend
    alias naively. Its body is ``commitmentIds: [{commitmentId,
    spendDimension}]`` — array of OBJECTS. A ``wrap: list`` alias moves
    commitmentId into the array but leaves spendDimension floating at
    the top level, yielding Amazon's cryptic "Expected null" error.
    Better UX is letting Amazon return the clear "field required"
    instead. If this test starts passing with a non-empty rewrite,
    check that whoever added the alias also scrubs spendDimension /
    composes a full object — otherwise remove the rule."""
    middleware = _middleware()
    sample_in = {"commitmentId": "c-1", "spendDimension": "DAILY"}
    rewritten = await middleware.rewrite_args(tool_name, sample_in)
    assert "commitmentIds" not in rewritten, (
        f"{tool_name}: an alias now rewrites commitmentId, but the DSP "
        "shape is array-of-OBJECTS. Either scrub top-level keys after "
        "the wrap, or revert the rule."
    )
