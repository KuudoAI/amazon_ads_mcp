"""Integration tests for Amazon Ads MCP server bootstrap.

This module tests the server creation and bootstrap process,
ensuring the server can be properly initialized with OpenAPI
specifications.

Credentials and ``CODE_MODE=false`` come from ``tests/conftest.py`` autouse
fixtures (``AMAZON_AD_API_*`` env vars and rebinding imported ``settings``).
"""

import pathlib

import pytest


@pytest.mark.asyncio
async def test_create_server_bootstrap():
    # Only run if resources directory exists; otherwise skip
    from amazon_ads_mcp.server.mcp_server import create_amazon_ads_server

    root = pathlib.Path(__file__).parents[2]
    resources = root / "openapi" / "resources"
    if not resources.exists():
        pytest.skip("No openapi/resources present in repo")

    srv = await create_amazon_ads_server()
    assert srv is not None
