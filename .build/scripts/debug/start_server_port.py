#!/usr/bin/env python3
"""Start the Amazon Ads MCP server on a specific port using SSE transport."""

import asyncio
import logging
import os
from fastmcp import FastMCP
from fastmcp.server import Server

from amazon_ads_mcp.server.main_dynamic import create_dynamic_amazon_ads_server

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


async def main():
    """Start the MCP server on port 9080."""
    # Create the MCP server instance
    mcp = await create_dynamic_amazon_ads_server()
    
    # Create SSE server on port 9080
    logger.info("Starting Amazon Ads MCP server on port 9080...")
    
    # Run with SSE transport on specified port
    await mcp.run(
        transport="sse",
        sse_port=9080,
        sse_host="0.0.0.0"  # Listen on all interfaces
    )


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {e}")
        raise