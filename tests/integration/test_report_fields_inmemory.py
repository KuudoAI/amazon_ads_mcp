"""In-memory MCP integration tests for the report_fields tool.

Exercises the real FastMCP protocol over the in-memory transport:
- mode="query" returns the expected shape
- mode="validate" returns validation diagnostics
- no-arg query is rejected with ToolError / INVALID_MODE_ARGS
- byte cap applies to the MCP-serialized payload flowing through call_tool
"""

from __future__ import annotations

import json
import pathlib

import pytest
import pytest_asyncio

pytest.importorskip("fastmcp")


@pytest_asyncio.fixture
async def mcp_server():
    """Full Amazon Ads MCP server with all builtin tools registered."""
    root = pathlib.Path(__file__).parents[2]
    resources = root / "openapi" / "resources"
    if not resources.exists():
        pytest.skip("No openapi/resources present in repo")

    from amazon_ads_mcp.server.mcp_server import create_amazon_ads_server

    return await create_amazon_ads_server()


def _extract_json(result) -> dict:
    """Parse the first TextContent payload of a CallToolResult."""
    assert result is not None
    assert result.content
    first = result.content[0]
    assert hasattr(first, "text"), f"unexpected content type: {type(first)}"
    return json.loads(first.text)


class TestReportFieldsInMemory:
    @pytest.mark.asyncio
    async def test_query_mode_returns_expected_shape(self, mcp_server):
        from fastmcp import Client

        async with Client(mcp_server) as client:
            result = await client.call_tool(
                "report_fields",
                {"mode": "query", "category": "metric", "search": "click", "limit": 5},
            )
            data = _extract_json(result)

        assert data["success"] is True
        assert data["mode"] == "query"
        assert data["operation"] == "allv1_AdsApiv1CreateReport"
        assert data["catalog_schema_version"] == 1
        # At least one "click"-related metric shows up (case-insensitive match).
        ids = [e["field_id"] for e in data["fields"]]
        assert ids, "expected at least one match for search='click'"
        assert all(e["category"] == "metric" for e in data["fields"])
        assert any("click" in fid.lower() for fid in ids)

    @pytest.mark.asyncio
    async def test_validate_mode_flags_unknown_and_known(self, mcp_server):
        from fastmcp import Client

        async with Client(mcp_server) as client:
            result = await client.call_tool(
                "report_fields",
                {
                    "mode": "validate",
                    "operation": "allv1_AdsApiv1CreateReport",
                    "validate_fields": ["metric.clicks", "metric.click"],
                },
            )
            data = _extract_json(result)

        assert data["mode"] == "validate"
        assert data["valid"] is False
        assert "metric.click" in data["unknown_fields"]
        # typo suggestion points at the real field
        assert "metric.clicks" in data["suggested_replacements"].get("metric.click", [])

    @pytest.mark.asyncio
    async def test_query_mode_with_no_args_raises_tool_error(self, mcp_server):
        from fastmcp import Client
        from fastmcp.exceptions import ToolError

        async with Client(mcp_server) as client:
            with pytest.raises(ToolError) as excinfo:
                await client.call_tool("report_fields", {"mode": "query"})
            # Error message mentions the locked code so agents can parse it.
            assert "INVALID_MODE_ARGS" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_byte_cap_applies_to_serialized_payload(self, mcp_server, monkeypatch):
        """Byte cap is enforced on the MCP-serialized response, not the Python object."""
        from fastmcp import Client

        monkeypatch.setenv("LIST_REPORT_FIELDS_MAX_BYTES", "1024")

        async with Client(mcp_server) as client:
            result = await client.call_tool(
                "report_fields",
                {"mode": "query", "category": "metric", "limit": 50},
            )
            data = _extract_json(result)
            # Serialized payload must be within the cap or set truncated=true.
            payload_bytes = len(
                json.dumps(data, separators=(",", ":")).encode("utf-8")
            )
            if payload_bytes > 1024:
                assert data.get("truncated") is True
                assert data.get("truncated_reason") == "byte_cap"
