"""Round 4 #1: ``arg_aliases`` rewrites must emit ``_meta.normalized``
events so agents see when their input was rewritten (Ads).

Mirrors the SP test of the same name. Verifies the executor populates
``_CURRENT_NORMALIZATION_EVENTS`` so ``MetaInjectionMiddleware`` can
surface the rewrite on success.
"""

from __future__ import annotations

import pytest

from amazon_ads_mcp.middleware.schema_normalization import (
    _CURRENT_NORMALIZATION_EVENTS,
    get_current_normalization_events,
)
from amazon_ads_mcp.server.transform_executor import DeclarativeTransformExecutor


@pytest.fixture(autouse=True)
def _reset_normalization_events_var():
    token = _CURRENT_NORMALIZATION_EVENTS.set([])
    try:
        yield
    finally:
        _CURRENT_NORMALIZATION_EVENTS.reset(token)


@pytest.mark.asyncio
async def test_arg_aliases_rewrite_emits_renamed_event():
    rule = {
        "match": {"operationId": "x"},
        "input_transform": {
            "arg_aliases": [{"from": "AccessLevel", "to": "accessLevel"}]
        },
    }
    executor = DeclarativeTransformExecutor(
        namespace="test", rules={"version": "1.0", "tools": [rule]}
    )
    transform = executor.create_input_transform(rule)
    assert transform is not None

    out = await transform({"AccessLevel": "VIEW"})
    assert out["accessLevel"] == "VIEW"

    events = get_current_normalization_events() or []
    kinds = [e.get("kind") for e in events]
    assert "renamed" in kinds
    rename = next(e for e in events if e.get("kind") == "renamed")
    assert rename["from"] == "AccessLevel"
    assert rename["to"] == "accessLevel"
    assert rename.get("reason") == "arg_alias"


@pytest.mark.asyncio
async def test_arg_aliases_with_wrap_list_emits_coerced_event():
    rule = {
        "match": {"operationId": "x"},
        "input_transform": {
            "arg_aliases": [
                {"from": "reportId", "to": "reportIds", "wrap": "list"}
            ]
        },
    }
    executor = DeclarativeTransformExecutor(
        namespace="test", rules={"version": "1.0", "tools": [rule]}
    )
    transform = executor.create_input_transform(rule)

    out = await transform({"reportId": "abc-123"})
    assert out["reportIds"] == ["abc-123"]

    events = get_current_normalization_events() or []
    kinds = [e.get("kind") for e in events]
    assert "renamed" in kinds
    assert "coerced" in kinds


@pytest.mark.asyncio
async def test_arg_aliases_skip_when_canonical_present_emits_nothing():
    rule = {
        "match": {"operationId": "x"},
        "input_transform": {
            "arg_aliases": [{"from": "AccessLevel", "to": "accessLevel"}]
        },
    }
    executor = DeclarativeTransformExecutor(
        namespace="test", rules={"version": "1.0", "tools": [rule]}
    )
    transform = executor.create_input_transform(rule)

    await transform({"accessLevel": "already-set", "AccessLevel": "ignored"})

    events = get_current_normalization_events() or []
    assert events == []


@pytest.mark.asyncio
async def test_arg_aliases_skip_when_source_missing_emits_nothing():
    rule = {
        "match": {"operationId": "x"},
        "input_transform": {
            "arg_aliases": [{"from": "AccessLevel", "to": "accessLevel"}]
        },
    }
    executor = DeclarativeTransformExecutor(
        namespace="test", rules={"version": "1.0", "tools": [rule]}
    )
    transform = executor.create_input_transform(rule)

    await transform({"unrelated": "value"})

    events = get_current_normalization_events() or []
    assert events == []
