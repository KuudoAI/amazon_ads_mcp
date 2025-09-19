#!/usr/bin/env python3
"""Test the MCP server functionality."""

import asyncio
import json
import os
from pathlib import Path

from dotenv import load_dotenv

# Enable experimental parser BEFORE importing
os.environ["FASTMCP_EXPERIMENTAL_ENABLE_NEW_OPENAPI_PARSER"] = "true"

from src.amazon_ads_mcp.server.main import create_test_account_server

# Load environment variables
load_dotenv()


async def test_mcp_server():
    """Test the MCP server setup."""
    print("🚀 Testing MCP Server Setup")
    print("=" * 50)
    
    # Check if OpenAPI spec exists
    spec_path = Path("openapi/test_account.json")
    if not spec_path.exists():
        print("❌ OpenAPI spec not found at openapi/test_account.json")
        print("   The spec should have been downloaded already.")
        return
    
    print("✅ OpenAPI spec found")
    
    # Try to create the MCP server
    try:
        print("\n📡 Creating MCP server...")
        mcp = await create_test_account_server()
        print("✅ MCP server created successfully")
        
        # Display server info
        print(f"\n📋 Server Info:")
        print(f"   Name: {mcp.name}")
        
        # List available tools - check different attributes based on parser
        tools = None
        if hasattr(mcp, 'tools'):
            tools = mcp.tools
        elif hasattr(mcp, '_tools'):
            tools = mcp._tools
        elif hasattr(mcp, 'mcp') and hasattr(mcp.mcp, 'tools'):
            tools = mcp.mcp.tools
            
        if tools:
            print("\n🔧 Available Tools:")
            if isinstance(tools, dict):
                for tool_name, tool in tools.items():
                    print(f"   - {tool_name}")
                    if hasattr(tool, "description"):
                        print(f"     {tool.description}")
            else:
                print(f"   Found {len(tools)} tools")
        else:
            print("\n🔧 Tools not directly accessible (this is normal for OpenAPI servers)")
        
        print("\n✅ Server is ready to run!")
        print("   Use 'make run' to start the server")
        
    except Exception as e:
        print(f"\n❌ Failed to create MCP server: {e}")
        print("\n🔍 Troubleshooting:")
        print("   1. Check that credentials are set in .env file")
        print("   2. Verify the OpenAPI spec is valid")
        print("   3. Check the error message above")


if __name__ == "__main__":
    asyncio.run(test_mcp_server())