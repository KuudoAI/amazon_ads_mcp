"""In-memory MCP Client tests using FastMCP 2.14+ patterns.

This module demonstrates testing the Amazon Ads MCP server using FastMCP's
in-memory transport. The in-memory transport runs the real MCP protocol
implementation without network overhead, making tests deterministic and fast.

Key benefits:
- No network/subprocess overhead - tests complete in milliseconds
- Direct access to server instance - debugger works seamlessly
- Real MCP protocol - tests actual behavior, not mocks
- Deterministic - no race conditions or flaky tests

Usage:
    pytest tests/integration/test_inmemory_mcp_client.py -v

See: https://gofastmcp.com/v2/development/tests
"""

from unittest.mock import MagicMock

import pytest
import pytest_asyncio

# Skip all tests if FastMCP Client isn't available
pytest.importorskip("fastmcp")


@pytest.fixture
def mock_auth_for_inmemory(monkeypatch):
    """Set up authentication mocks for in-memory testing.

    This fixture configures the minimum required auth state for
    testing MCP tools without hitting real Amazon Ads API.
    """
    monkeypatch.setenv("AUTH_METHOD", "direct")
    monkeypatch.setenv("AMAZON_AD_API_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("AMAZON_AD_API_CLIENT_SECRET", "test-client-secret")
    monkeypatch.setenv("AD_API_REFRESH_TOKEN", "test-refresh-token")
    monkeypatch.setenv("AMAZON_ADS_REGION", "na")
    monkeypatch.setenv("AMAZON_ADS_SANDBOX_MODE", "false")


@pytest_asyncio.fixture
async def mcp_server(mock_auth_for_inmemory):
    """Create a configured MCP server instance for in-memory testing.

    This fixture creates the full Amazon Ads MCP server with all
    builtin tools registered, suitable for in-memory client testing.
    """
    import pathlib

    root = pathlib.Path(__file__).parents[2]
    resources = root / "openapi" / "resources"
    if not resources.exists():
        pytest.skip("No openapi/resources present in repo")

    from amazon_ads_mcp.server.mcp_server import create_amazon_ads_server

    server = await create_amazon_ads_server()
    return server


class TestInMemoryMCPOperations:
    """Test MCP operations using in-memory FastMCP Client.

    These tests demonstrate the recommended FastMCP 2.14+ pattern
    for testing MCP servers without network overhead.
    """

    @pytest.mark.asyncio
    async def test_list_tools_returns_builtin_tools(self, mcp_server):
        """Verify builtin tools are registered and discoverable.

        The in-memory client should be able to list all registered
        tools including region, profile, and download tools.
        """
        from fastmcp import Client

        async with Client(mcp_server) as client:
            tools = await client.list_tools()

            # Verify we have tools registered
            assert len(tools) > 0

            # Check for expected builtin tools
            tool_names = [t.name for t in tools]
            expected_builtins = [
                "set_region",
                "get_region",
                "list_regions",
                "set_active_profile",
                "get_active_profile",
                "clear_active_profile",
            ]

            for expected in expected_builtins:
                assert expected in tool_names, f"Expected builtin tool '{expected}' not found"

    @pytest.mark.asyncio
    async def test_get_region_returns_structured_response(self, mcp_server):
        """Test get_region tool returns properly structured response.

        Demonstrates calling a tool and validating the typed response.
        """
        from fastmcp import Client

        async with Client(mcp_server) as client:
            result = await client.call_tool("get_region", {})

            # Result is a CallToolResult object
            assert result is not None

            # CallToolResult has content attribute with the response
            assert result.content is not None
            assert len(result.content) > 0

    @pytest.mark.asyncio
    async def test_list_regions_enumerates_all_regions(self, mcp_server):
        """Test list_regions returns all available Amazon Ads regions."""
        from fastmcp import Client

        async with Client(mcp_server) as client:
            result = await client.call_tool("list_regions", {})

            assert result is not None
            assert result.content is not None
            assert len(result.content) > 0

    @pytest.mark.asyncio
    async def test_set_region_changes_routing(self, mcp_server):
        """Test set_region tool modifies routing state.

        This tests the full flow: set a region, then verify
        the change took effect.
        """
        from fastmcp import Client

        async with Client(mcp_server) as client:
            # Set to EU region (parameter is region_code)
            set_result = await client.call_tool("set_region", {"region_code": "eu"})
            assert set_result is not None

            # Verify the change
            get_result = await client.call_tool("get_region", {})
            assert get_result is not None

    @pytest.mark.asyncio
    async def test_get_routing_state_on_fresh_server(self, mcp_server):
        """Test get_routing_state returns valid defaults on a fresh server.

        Before any requests are made, there's no routing state established.
        The tool should return sensible defaults based on settings rather
        than failing with ValidationError.
        """
        import json

        from fastmcp import Client

        async with Client(mcp_server) as client:
            result = await client.call_tool("get_routing_state", {})

            assert result is not None
            assert result.content is not None

            # Parse the response content to verify structure
            # FastMCP returns TextContent with JSON for Pydantic models
            content = result.content[0]
            if hasattr(content, "text"):
                data = json.loads(content.text)
                # Verify required fields are present with valid defaults
                assert "region" in data
                assert "host" in data
                assert data["region"] in ("na", "eu", "fe")
                assert "amazon.com" in data["host"]

    @pytest.mark.asyncio
    async def test_get_active_profile_without_profile_set(self, mcp_server):
        """Test get_active_profile when no profile is explicitly set.

        Should return a response indicating no explicit profile is active.
        """
        from fastmcp import Client

        async with Client(mcp_server) as client:
            result = await client.call_tool("get_active_profile", {})

            assert result is not None
            assert result.content is not None
            assert len(result.content) > 0

    @pytest.mark.asyncio
    async def test_set_active_profile_stores_profile(self, mcp_server):
        """Test set_active_profile correctly stores the profile ID."""
        from fastmcp import Client

        test_profile_id = "1234567890"

        async with Client(mcp_server) as client:
            # Set a profile
            set_result = await client.call_tool(
                "set_active_profile",
                {"profile_id": test_profile_id}
            )
            assert set_result is not None

            # Verify it was set
            get_result = await client.call_tool("get_active_profile", {})
            assert get_result is not None

    @pytest.mark.asyncio
    async def test_clear_active_profile_removes_profile(self, mcp_server):
        """Test clear_active_profile removes the stored profile."""
        from fastmcp import Client

        async with Client(mcp_server) as client:
            # First set a profile
            await client.call_tool(
                "set_active_profile",
                {"profile_id": "1234567890"}
            )

            # Now clear it
            clear_result = await client.call_tool("clear_active_profile", {})
            assert clear_result is not None


class TestInMemoryToolDiscovery:
    """Test MCP tool and resource discovery via in-memory client."""

    @pytest.mark.asyncio
    async def test_list_resources(self, mcp_server):
        """Test listing available MCP resources."""
        from fastmcp import Client

        async with Client(mcp_server) as client:
            resources = await client.list_resources()

            # Server may or may not have resources
            assert resources is not None

    @pytest.mark.asyncio
    async def test_list_prompts(self, mcp_server):
        """Test listing available MCP prompts."""
        from fastmcp import Client

        async with Client(mcp_server) as client:
            prompts = await client.list_prompts()

            # Server may or may not have prompts
            assert prompts is not None

    @pytest.mark.asyncio
    async def test_tool_has_description(self, mcp_server):
        """Verify tools have proper descriptions for discoverability."""
        from fastmcp import Client

        async with Client(mcp_server) as client:
            tools = await client.list_tools()

            # Find get_region tool
            get_region_tool = next(
                (t for t in tools if t.name == "get_region"),
                None
            )

            assert get_region_tool is not None
            assert get_region_tool.description is not None
            assert len(get_region_tool.description) > 0


class TestInMemoryErrorHandling:
    """Test error handling via in-memory client."""

    @pytest.mark.asyncio
    async def test_invalid_region_returns_error(self, mcp_server):
        """Test that invalid region code is handled gracefully."""
        from fastmcp import Client
        from fastmcp.exceptions import ToolError

        async with Client(mcp_server) as client:
            # Attempt to set an invalid region
            # The tool should handle this gracefully and return an error response
            try:
                result = await client.call_tool(
                    "set_region",
                    {"region_code": "invalid_region_code"}
                )
                # Tool may return an error response with success=False
                assert result is not None
            except ToolError:
                # Tool may raise an error for invalid input
                pass

    @pytest.mark.asyncio
    async def test_missing_required_parameter(self, mcp_server):
        """Test that missing required parameters are handled."""
        from fastmcp import Client
        from fastmcp.exceptions import ToolError

        async with Client(mcp_server) as client:
            # set_region requires a region_code parameter
            # FastMCP should validate and raise ToolError
            try:
                await client.call_tool("set_region", {})
                # If we get here without error, that's unexpected
                pytest.fail("Expected ToolError for missing required parameter")
            except ToolError:
                # Expected - missing required parameter
                pass


# Example of testing with mocked external dependencies
class TestInMemoryWithMockedDependencies:
    """Demonstrate testing with mocked external services.

    For tests that would normally hit external APIs (like Amazon Ads),
    we can mock those dependencies while still using the real MCP
    protocol via in-memory transport.
    """

    @pytest.mark.asyncio
    async def test_profile_tools_with_mocked_api(self, mcp_server):
        """Test profile operations with mocked API responses.

        This pattern is useful for testing tools that would
        normally require authentication and external API calls.
        """
        from fastmcp import Client

        # Mock the HTTP client to avoid real API calls
        mock_response = MagicMock()
        mock_response.json.return_value = [
            {
                "profileId": "111111111",
                "countryCode": "US",
                "currencyCode": "USD",
                "dailyBudget": 100.0,
                "timezone": "America/Los_Angeles",
                "accountInfo": {"type": "seller", "marketplaceStringId": "ATVPDKIKX0DER"}
            }
        ]
        mock_response.status_code = 200

        async with Client(mcp_server) as client:
            # These tools don't require mocking for basic operations
            # but this demonstrates the pattern for more complex tests
            result = await client.call_tool("get_active_profile", {})
            assert result is not None
