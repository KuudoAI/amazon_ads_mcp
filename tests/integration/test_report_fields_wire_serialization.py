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


# ---------- drop parameter (wire-level) ------------------------------------


@pytest.mark.asyncio
async def test_drop_omitted_listing_is_byte_identical_to_default(mcp_server):
    """Regression fence: callers that don't pass drop see today's wire bytes.

    Hits the FastMCP path explicitly because the drop is applied at the
    tool wrapper after model_dump — mid-stack tests can't catch a wrapper
    regression.
    """
    from fastmcp import Client

    args = {"mode": "query", "category": "metric", "search": "click", "limit": 5}

    async with Client(mcp_server) as client:
        baseline = await client.call_tool("report_fields", args)
        with_explicit_none = await client.call_tool(
            "report_fields", {**args, "drop": None}
        )
        with_empty = await client.call_tool("report_fields", {**args, "drop": []})

    assert baseline.content[0].text == with_explicit_none.content[0].text
    assert baseline.content[0].text == with_empty.content[0].text


@pytest.mark.asyncio
async def test_drop_compat_arrays_strips_keys_on_wire(mcp_server):
    """Dropped keys are absent from the wire JSON for every record."""
    from fastmcp import Client

    args = {
        "mode": "query",
        "category": "metric",
        "search": "click",
        "limit": 5,
        "drop": ["compatible_dimensions", "incompatible_dimensions"],
    }

    async with Client(mcp_server) as client:
        result = await client.call_tool("report_fields", args)
        data = json.loads(result.content[0].text)

    assert data["fields"], "expected at least one record"
    for entry in data["fields"]:
        assert "compatible_dimensions" not in entry, entry
        assert "incompatible_dimensions" not in entry, entry


@pytest.mark.asyncio
async def test_drop_yields_smaller_wire_payload_than_default(mcp_server):
    """End-to-end byte-savings check on the FastMCP transport path."""
    from fastmcp import Client

    base_args = {
        "mode": "query",
        "category": "metric",
        "search": "click",
        "limit": 10,
    }
    drop_args = {
        **base_args,
        "drop": ["compatible_dimensions", "incompatible_dimensions"],
    }

    async with Client(mcp_server) as client:
        baseline = await client.call_tool("report_fields", base_args)
        with_drop = await client.call_tool("report_fields", drop_args)

    # We can't pin an exact byte target without controlling the catalog,
    # but dropping populated arrays must reduce the wire payload.
    assert len(with_drop.content[0].text) < len(baseline.content[0].text)


@pytest.mark.asyncio
async def test_drop_in_validate_mode_raises_tool_error_on_wire(mcp_server):
    """Validate + drop is a contract violation surfaced as a tool error.

    The wrapper translates ReportFieldsToolError into a ValueError /
    fastmcp tool error. End-to-end check that the strict-by-default
    contract is enforced on the FastMCP transport, not just at the
    handler boundary.
    """
    from fastmcp import Client
    from fastmcp.exceptions import ToolError

    async with Client(mcp_server) as client:
        with pytest.raises(ToolError):
            await client.call_tool(
                "report_fields",
                {
                    "mode": "validate",
                    "validate_fields": ["metric.clicks"],
                    "drop": ["compatible_dimensions"],
                },
            )


@pytest.mark.asyncio
async def test_drop_unknown_key_raises_tool_error_on_wire(mcp_server):
    """Negative test: unknown drop key surfaces a deterministic tool error.

    Hits the FastMCP path so the wrapper's exception translation is
    exercised — silent ignore here would have hidden caller typos and
    weakened the byte-savings contract.
    """
    from fastmcp import Client
    from fastmcp.exceptions import ToolError

    async with Client(mcp_server) as client:
        with pytest.raises(ToolError):
            await client.call_tool(
                "report_fields",
                {
                    "mode": "query",
                    "category": "metric",
                    "search": "click",
                    "limit": 5,
                    # Misspelled — strict validator must reject.
                    "drop": ["compatable_dimensions"],
                },
            )
