#!/usr/bin/env python3
"""Test the dynamic MCP server with actual API calls."""

import asyncio
import json
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def test_dynamic_server():
    """Test various endpoints from the dynamic server."""
    server_params = StdioServerParameters(
        command=".venv/bin/python",
        args=["-m", "amazon_ads_mcp.server.main_dynamic"],
        env=None
    )
    
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            
            # List available tools
            tools = await session.list_tools()
            print(f"\n📊 Dynamic server loaded {len(tools.tools)} tools")
            
            # Sample some tools by category
            profiles_tools = [t for t in tools.tools if "/profiles" in t.name]
            campaigns_tools = [t for t in tools.tools if "/campaigns" in t.name]
            reports_tools = [t for t in tools.tools if "/report" in t.name]
            
            print(f"\n📁 Sample tools by category:")
            print(f"  - Profile management: {len(profiles_tools)} tools")
            print(f"  - Campaign management: {len(campaigns_tools)} tools")
            print(f"  - Reporting: {len(reports_tools)} tools")
            
            # Show first few tools from each category
            print("\n🔧 Sample Profile Tools:")
            for tool in profiles_tools[:3]:
                print(f"  - {tool.name}: {tool.description[:60]}...")
            
            print("\n🔧 Sample Campaign Tools:")
            for tool in campaigns_tools[:3]:
                print(f"  - {tool.name}: {tool.description[:60]}...")
            
            # Test a specific endpoint - get profiles
            print("\n🧪 Testing GET /v2/profiles endpoint...")
            try:
                result = await session.call_tool(
                    "get_v2_profiles",
                    arguments={}
                )
                
                if result.content:
                    # Parse the response
                    for content in result.content:
                        if content.type == "text":
                            try:
                                data = json.loads(content.text)
                                print(f"✅ Successfully retrieved {len(data)} profiles")
                                if data:
                                    print(f"   First profile: {data[0].get('profileId')} - {data[0].get('accountInfo', {}).get('marketplaceStringId', 'N/A')}")
                            except json.JSONDecodeError:
                                print(f"Response: {content.text[:200]}...")
                else:
                    print("❌ No content in response")
                    
            except Exception as e:
                print(f"❌ Error calling endpoint: {e}")
            
            # Test another endpoint - test account API
            print("\n🧪 Testing GET /testAccounts endpoint...")
            try:
                result = await session.call_tool(
                    "get_testAccounts",
                    arguments={}
                )
                
                if result.content:
                    for content in result.content:
                        if content.type == "text":
                            print(f"Response: {content.text[:200]}...")
                else:
                    print("❌ No content in response")
                    
            except Exception as e:
                print(f"❌ Error: {e}")
            
            print("\n✅ Dynamic server test completed!")


if __name__ == "__main__":
    asyncio.run(test_dynamic_server())