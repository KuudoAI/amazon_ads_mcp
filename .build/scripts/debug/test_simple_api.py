#!/usr/bin/env python3
"""Simple test to verify dynamic MCP server with actual API call."""

import asyncio
import json
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def test_api():
    """Test basic API call through the dynamic server."""
    server_params = StdioServerParameters(
        command=".venv/bin/python",
        args=["-m", "amazon_ads_mcp.server.main_dynamic"],
        env=None
    )
    
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            
            print("\n🧪 Testing Amazon Ads API - Simple Test")
            print("=" * 60)
            
            # Find and call test accounts endpoint
            tools = await session.list_tools()
            print(f"✅ Server loaded {len(tools.tools)} tools")
            
            # Look for test accounts endpoint
            for tool in tools.tools:
                if tool.name == "getTestAccounts":
                    print(f"\n📋 Found test accounts tool: {tool.name}")
                    try:
                        result = await session.call_tool(
                            tool.name,
                            arguments={}
                        )
                        
                        if result.content:
                            for content in result.content:
                                if content.type == "text":
                                    print(f"Response: {content.text[:500]}...")
                        else:
                            print("No content in response")
                    except Exception as e:
                        print(f"Error: {e}")
                    break
            
            print("\n" + "=" * 60)
            print("✅ Test completed!")


if __name__ == "__main__":
    asyncio.run(test_api())