#!/usr/bin/env python3
"""Test tool structure directly."""

import asyncio
import json
import logging
from amazon_ads_mcp.server.main_dynamic import create_dynamic_amazon_ads_server

# Silence logs
logging.getLogger("amazon_ads_mcp").setLevel(logging.ERROR)
logging.getLogger("fastmcp").setLevel(logging.ERROR)

async def test():
    """Test tool structure."""
    mcp = await create_dynamic_amazon_ads_server()
    print(f"Created MCP server: {mcp.name}")
    
    tools = await mcp.get_tools()
    print(f"\nTools type: {type(tools)}")
    
    if isinstance(tools, dict):
        print(f"Tools is a dict with keys: {list(tools.keys())}")
        if 'tools' in tools:
            tools_list = tools['tools']
            print(f"\nGot {len(tools_list)} tools")
            
            if tools_list:
                print(f"\nFirst tool:")
                print(f"  Type: {type(tools_list[0])}")
                print(f"  Value: {tools_list[0]}")
                
                print(f"\nFirst 3 tools:")
                for i, tool in enumerate(tools_list[:3]):
                    print(f"  Tool {i}: {tool}")
    else:
        print(f"Got {len(tools)} tools")
        if tools:
            print(f"\nFirst tool:")
            print(f"  Type: {type(tools[0])}")
            print(f"  Value: {tools[0]}")
            
            print(f"\nFirst 3 tools:")
            for i, tool in enumerate(tools[:3]):
                print(f"  Tool {i}: {tool}")

if __name__ == "__main__":
    asyncio.run(test())