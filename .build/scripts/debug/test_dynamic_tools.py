#!/usr/bin/env python3
"""List and test available tools in the dynamic MCP server."""

import asyncio
import json
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def test_dynamic_tools():
    """List and test tools from the dynamic server."""
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
            
            # Find profile-related tools
            print("\n🔍 Looking for profile-related tools:")
            profile_tools = []
            for tool in tools.tools[:20]:  # Check first 20 tools
                print(f"  - {tool.name}")
                if "profile" in tool.name.lower():
                    profile_tools.append(tool)
            
            # Show tools that contain "test"
            print("\n🔍 Looking for test account tools:")
            test_tools = []
            for tool in tools.tools:
                if "test" in tool.name.lower():
                    print(f"  - {tool.name}: {tool.description[:50]}...")
                    test_tools.append(tool)
                    if len(test_tools) >= 5:
                        break
            
            # Try to call the first available tool
            if tools.tools:
                first_tool = tools.tools[0]
                print(f"\n🧪 Testing first available tool: {first_tool.name}")
                print(f"   Description: {first_tool.description}")
                
                try:
                    # Build arguments based on input schema
                    args = {}
                    if first_tool.inputSchema and "properties" in first_tool.inputSchema:
                        print(f"   Parameters: {list(first_tool.inputSchema['properties'].keys())}")
                    
                    result = await session.call_tool(first_tool.name, arguments=args)
                    
                    if result.content:
                        for content in result.content:
                            if content.type == "text":
                                print(f"   Response: {content.text[:200]}...")
                    else:
                        print("   No content in response")
                        
                except Exception as e:
                    print(f"   Error: {e}")
            
            print("\n✅ Tool listing completed!")


if __name__ == "__main__":
    asyncio.run(test_dynamic_tools())