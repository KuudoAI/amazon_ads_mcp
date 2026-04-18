"""Pins Issue 6 (bug_fix_plan.md §6) — reportId singular alias transform.

The alias is declared in openapi/resources/AdsAPIv1All.transform.json:
    match.operationId == "AdsApiv1RetrieveReport"
    input_transform.arg_aliases = [{"from":"reportId","to":"reportIds","wrap":"list"}]

This test verifies the create_input_transform pipeline applies that rule
correctly: singular reportId="abc" is rewritten to reportIds=["abc"]
before the outbound API call.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from amazon_ads_mcp.server.transform_executor import DeclarativeTransformExecutor

TRANSFORM_PATH = (
    Path(__file__).resolve().parents[2]
    / "openapi"
    / "resources"
    / "AdsAPIv1All.transform.json"
)


def _find_rule(operation_id: str) -> dict:
    """The transform file stores rules under the `tools` key."""
    data = json.loads(TRANSFORM_PATH.read_text())
    for rule in data.get("tools", []):
        if rule.get("match", {}).get("operationId") == operation_id:
            return rule
    raise LookupError(f"no transform rule for operationId={operation_id!r}")


@pytest.mark.asyncio
async def test_report_id_singular_wraps_to_list():
    rule = _find_rule("AdsApiv1RetrieveReport")
    executor = DeclarativeTransformExecutor(namespace="allv1", rules={})
    transform = executor.create_input_transform(rule)
    assert transform is not None

    result = await transform({"reportId": "abc-123"})

    assert result.get("reportIds") == ["abc-123"], (
        f"expected singular reportId to wrap to list; got {result!r}"
    )


@pytest.mark.asyncio
async def test_report_ids_plural_passes_through_untouched():
    rule = _find_rule("AdsApiv1RetrieveReport")
    executor = DeclarativeTransformExecutor(namespace="allv1", rules={})
    transform = executor.create_input_transform(rule)
    assert transform is not None

    result = await transform({"reportIds": ["a", "b"]})
    assert result.get("reportIds") == ["a", "b"]
    assert "reportId" not in result or result.get("reportId") in (None, "")


@pytest.mark.asyncio
async def test_both_forms_plural_wins():
    """If both are provided, the already-present reportIds must not be overwritten."""
    rule = _find_rule("AdsApiv1RetrieveReport")
    executor = DeclarativeTransformExecutor(namespace="allv1", rules={})
    transform = executor.create_input_transform(rule)

    result = await transform(
        {"reportId": "singular-x", "reportIds": ["plural-y"]}
    )
    assert result.get("reportIds") == ["plural-y"], (
        "pre-existing reportIds must win over the alias"
    )
