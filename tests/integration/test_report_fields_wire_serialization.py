"""Wire-serialization tests for report_fields — pins Issue 13 (bug_fix_plan §4).

The handler emits Pydantic models with None-valued optional fields. Those
must drop out of the JSON payload flowing through MCP so that
`include_v3_mapping=False` yields an entry without the v3 keys, not an
entry with `null` v3 keys. Fixed by returning model_dump(exclude_none=True)
as a dict from the tool wrapper.
"""

from __future__ import annotations

import json
import pathlib

import pytest
import pytest_asyncio

pytest.importorskip("fastmcp")


@pytest_asyncio.fixture
async def mcp_server():
    root = pathlib.Path(__file__).parents[2]
    if not (root / "openapi" / "resources").exists():
        pytest.skip("No openapi/resources present in repo")
    from amazon_ads_mcp.server.mcp_server import create_amazon_ads_server

    return await create_amazon_ads_server()


def _first_entry(payload: dict) -> dict:
    return payload["fields"][0]


@pytest.mark.asyncio
async def test_include_v3_mapping_false_drops_v3_keys(mcp_server):
    """include_v3_mapping=False must produce entries WITHOUT v3 keys (not null)."""
    from fastmcp import Client

    async with Client(mcp_server) as client:
        result = await client.call_tool(
            "report_fields",
            {
                "mode": "query",
                "category": "metric",
                "search": "click",
                "limit": 2,
                "include_v3_mapping": False,
            },
        )
        data = json.loads(result.content[0].text)

    entry = _first_entry(data)
    assert "v3_name_dsp" not in entry, (
        f"v3_name_dsp must be absent when include_v3_mapping=False; "
        f"got keys {sorted(entry.keys())}"
    )
    assert "v3_name_sponsored_ads" not in entry


@pytest.mark.asyncio
async def test_include_v3_mapping_true_emits_v3_keys_with_values(mcp_server):
    from fastmcp import Client

    async with Client(mcp_server) as client:
        result = await client.call_tool(
            "report_fields",
            {
                "mode": "query",
                "category": "metric",
                "search": "click",
                "limit": 2,
                "include_v3_mapping": True,
            },
        )
        data = json.loads(result.content[0].text)

    entry = _first_entry(data)
    # Keys must be present; at least one of the two should have a non-null
    # value for a click metric (Amazon maps most metrics to v3).
    assert "v3_name_dsp" in entry or "v3_name_sponsored_ads" in entry


@pytest.mark.asyncio
async def test_listing_mode_drops_detail_only_keys(mcp_server):
    """description/source/compatible_metrics/incompatible_metrics are detail-only."""
    from fastmcp import Client

    async with Client(mcp_server) as client:
        result = await client.call_tool(
            "report_fields",
            {"mode": "query", "category": "metric", "limit": 2},
        )
        data = json.loads(result.content[0].text)

    for entry in data["fields"]:
        assert "description" not in entry, (
            "description is detail-only; must not appear in listing entries"
        )
        assert "source" not in entry, (
            "source is detail-only; must not appear in listing entries"
        )
        # Metric records never carry inverted-index fields.
        assert "compatible_metrics" not in entry
        assert "incompatible_metrics" not in entry


@pytest.mark.asyncio
async def test_detail_lookup_emits_description_and_source(mcp_server):
    from fastmcp import Client

    async with Client(mcp_server) as client:
        result = await client.call_tool(
            "report_fields",
            {"mode": "query", "fields": ["metric.clicks"]},
        )
        data = json.loads(result.content[0].text)

    assert data["fields"], "expected one record for metric.clicks"
    entry = data["fields"][0]
    # Full detail path populates these, so keys must be present.
    assert "description" in entry
    assert "source" in entry
    assert entry["source"]["parsed_at"], "source.parsed_at must be populated"
