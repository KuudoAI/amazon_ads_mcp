"""Unit tests for transform shaping.

This module tests the transform execution functionality that
shapes and processes API responses according to declarative rules.
"""

import asyncio

from amazon_ads_mcp.server.transform_executor import DeclarativeTransformExecutor


def run(coro):
    return asyncio.run(coro)


async def _call_next_echo(args):
    # Echo a structure with lists for shaping
    return {
        "items": list(range(0, 100)),
        "details": {"columns": [f"c{i}" for i in range(50)], "foo": "bar"},
        "status": "ok",
    }


def test_call_transform_shapes_output_with_args():
    rules = {"version": "1.0"}
    ex = DeclarativeTransformExecutor("AMCWorkflow", rules)
    rule = {
        "match": {"operationId": "listWorkflowExecutions"},
        "output_transform": {
            "projection": ["items", "status", "details"],
            "sample_n": 10,
            "artifact_threshold_bytes": 10_000_000,
        },
    }
    call_tx = ex.create_call_transform(rule)
    shaped = run(call_tx(_call_next_echo, {"sample_n": 5}))
    assert len(shaped["items"]) == 5
    assert len(shaped["details"]["columns"]) == 5


def test_input_transform_parses_and_composes():
    rules = {"version": "1.0"}
    ex = DeclarativeTransformExecutor("Test", rules)
    rule = {
        "input_transform": {
            "parse_payload": "json_or_yaml",
            "coerce": ["enum_case"],
            "compose": {"payload": "$payload", "status": "$status"},
        }
    }
    input_tx = ex.create_input_transform(rule)
    result = run(input_tx({"payload": "{\"foo\": \"bar\"}", "status": "ok"}))
    assert result["payload"]["foo"] == "BAR"
    assert result["status"] == "OK"


def test_call_transform_pagination_all_pages():
    rules = {"version": "1.0"}
    ex = DeclarativeTransformExecutor("Test", rules)
    rule = {"pagination": {"all_pages": True, "param_name": "nextToken"}}
    call_tx = ex.create_call_transform(rule)

    async def call_next(args):
        token = args.get("nextToken")
        if token is None:
            return {"items": [1], "nextToken": "next"}
        return {"items": [2], "nextToken": None}

    result = run(call_tx(call_next, {}))
    assert result["pages"] == 2
    assert result["results"][0]["items"] == [1]
    assert result["results"][1]["items"] == [2]


def test_call_transform_batching_merges_items():
    rules = {"version": "1.0"}
    ex = DeclarativeTransformExecutor("Test", rules)
    rule = {"batch": {"size": 2, "path": "payload"}}
    call_tx = ex.create_call_transform(rule)

    async def call_next(args):
        return {"items": list(args.get("payload", []))}

    result = run(call_tx(call_next, {"payload": [1, 2, 3, 4]}))
    assert result["count"] == 4
    assert result["items"] == [1, 2, 3, 4]
