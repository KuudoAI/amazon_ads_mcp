#!/usr/bin/env python3
"""Run the Amazon Ads MCP server with SSE transport on port 9080."""

import asyncio
import os
import sys

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Set up environment
os.environ["FASTMCP_PORT"] = "9080"
os.environ["FASTMCP_TRANSPORT"] = "sse"

# Import and run the main server
from amazon_ads_mcp.server.main_dynamic import main

if __name__ == "__main__":
    # Run the dynamic server with SSE transport
    import subprocess
    subprocess.run([
        sys.executable, "-m", "amazon_ads_mcp.server.main_dynamic"
    ], env={**os.environ, "FASTMCP_PORT": "9080", "FASTMCP_TRANSPORT": "sse"})