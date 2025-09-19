#!/usr/bin/env python3
"""List all available tools in the dynamic MCP server."""

import asyncio
import json
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def list_all_tools():
    """List all tools from the dynamic server."""
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
            
            # Group tools by category (based on path prefix)
            categories = {}
            for tool in tools.tools:
                # Extract category from tool name
                parts = tool.name.split('_')
                if len(parts) > 1:
                    category = parts[0]
                else:
                    category = "Other"
                
                if category not in categories:
                    categories[category] = []
                categories[category].append(tool)
            
            # Print tools by category
            for category, cat_tools in sorted(categories.items()):
                print(f"\n📁 {category} ({len(cat_tools)} tools):")
                for tool in sorted(cat_tools, key=lambda x: x.name)[:5]:  # Show first 5
                    print(f"  - {tool.name}")
                if len(cat_tools) > 5:
                    print(f"  ... and {len(cat_tools) - 5} more")
            
            # Look for specific tools
            print("\n🔍 Sample endpoints:")
            sample_names = ["listProfiles", "getTestAccounts", "listTestAccountsAction", 
                          "ListSponsoredProductsCampaigns", "CreateReport"]
            
            for name in sample_names:
                found = [t for t in tools.tools if name.lower() in t.name.lower()]
                if found:
                    print(f"\n✅ Found '{name}':")
                    for tool in found[:2]:
                        print(f"  - {tool.name}")
                else:
                    print(f"\n❌ Not found: '{name}'")


if __name__ == "__main__":
    asyncio.run(list_all_tools())