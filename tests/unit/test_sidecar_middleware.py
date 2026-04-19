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
    middleware = SidecarTransformMiddleware(RESOURCES_DIR)
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
    middleware = SidecarTransformMiddleware(RESOURCES_DIR)
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
    middleware = SidecarTransformMiddleware(RESOURCES_DIR)
    ctx = _make_context("nonexistent_tool", {"a": 1, "b": 2})

    captured: list[dict] = []

    async def call_next(c):
        captured.append(dict(c.message.arguments))
        return "ok"

    await middleware.on_call_tool(ctx, call_next)
    assert captured[0] == {"a": 1, "b": 2}


@pytest.mark.asyncio
async def test_middleware_stats_count_loaded_rules():
    middleware = SidecarTransformMiddleware(RESOURCES_DIR)
    stats = middleware.stats()
    # We know at least the reportId alias rule loaded.
    assert stats["compiled_transforms"] >= 1
    assert stats["tools_with_transforms"] >= 1
    assert stats["rules"] >= stats["compiled_transforms"]


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
        # Original RetrieveReport alias (both All + Beta specs).
        ("allv1_AdsApiv1RetrieveReport", "reportId", "reportIds"),
        ("beta_AdsApiv1RetrieveReport", "reportId", "reportIds"),
        # Same plural-of-one shape, discovered via minItems/maxItems sweep.
        ("allv1_AdsApiv1DeleteReport", "reportId", "reportIds"),
        ("beta_AdsApiv1DeleteReport", "reportId", "reportIds"),
        ("allv1_DSPRetrieveCommitmentSpend", "commitmentId", "commitmentIds"),
    ],
)
async def test_singular_aliases_across_plural_of_one_endpoints(
    tool_name, singular_key, plural_key
):
    """Every endpoint whose requestBody is a plural-array-of-one (minItems=1,
    maxItems=1) should accept the natural singular via an arg_aliases rule.
    This catches regressions where the rule gets accidentally dropped
    during transform-file edits."""
    middleware = SidecarTransformMiddleware(RESOURCES_DIR)
    rewritten = await middleware.rewrite_args(tool_name, {singular_key: "abc"})
    assert rewritten.get(plural_key) == ["abc"], (
        f"{tool_name}: singular {singular_key!r} did not rewrite to "
        f"{plural_key!r}; got {rewritten!r}"
    )
