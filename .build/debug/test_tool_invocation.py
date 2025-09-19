#!/usr/bin/env python3
"""
Test actual tool invocation through mounted servers.
"""

import asyncio
import os
import sys
from pathlib import Path
import json
import logging

# Add project to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

# Enable debug logging
os.environ["LOG_LEVEL"] = "DEBUG"
os.environ["OPENBRIDGE_REMOTE_IDENTITY_ID"] = "12927"

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

from amazon_ads_mcp.server.mcp_server import create_amazon_ads_server


async def test_tool_invocation():
    """Test invoking a tool through the mounted server."""
    
    print("="*80)
    print("TESTING TOOL INVOCATION FOR EU PROFILE")
    print("="*80)
    
    # Create the server
    print("\n1. Creating Amazon Ads MCP server...")
    server = await create_amazon_ads_server()
    
    # List available tools
    print("\n2. Listing available tools through MCP protocol...")
    tools = await server._mcp_list_tools()
    print(f"   Total tools available: {len(tools)}")
    
    # Find profile tools
    profile_tools = [t for t in tools if 'profile' in t.name.lower()]
    print(f"   Profile-related tools: {len(profile_tools)}")
    for tool in profile_tools[:10]:
        print(f"     - {tool.name}: {tool.description[:50] if tool.description else ''}...")
    
    # Find the getProfile tool
    get_profile_tool = None
    for tool in tools:
        if 'getprofile' in tool.name.lower() and 'ap_' in tool.name.lower():
            get_profile_tool = tool
            break
    
    if get_profile_tool:
        print(f"\n3. Found tool: {get_profile_tool.name}")
        print(f"   Description: {get_profile_tool.description[:100] if get_profile_tool.description else 'No description'}...")
        
        # Try to call the tool
        print(f"\n4. Calling {get_profile_tool.name} with profileId=3433820656974170...")
        print("   Watch for debug logs showing region routing and headers...")
        print("-" * 40)
        
        try:
            # Call the tool directly through the MCP protocol
            result = await server._mcp_call_tool(
                key=get_profile_tool.name,
                arguments={"profileId": "3433820656974170"}
            )
            
            print("-" * 40)
            print(f"\n5. Tool result:")
            if isinstance(result, list) and result:
                content = result[0].content if hasattr(result[0], 'content') else result[0]
                print(f"   {str(content)[:500]}")
            else:
                print(f"   {str(result)[:500]}")
            
        except Exception as e:
            print(f"\n❌ Tool invocation failed: {e}")
            import traceback
            traceback.print_exc()
    else:
        print("\n❌ No getProfile tool found")
        print("   Available profile tools:")
        for tool in profile_tools:
            print(f"     - {tool.name}")
    
    print("\n" + "="*80)
    print("ANALYSIS")
    print("="*80)
    print("""
Check the logs for:
1. "Region routing decided:" - Should show EU region
2. "Adding auth headers" - Should show headers being added
3. HTTP request URL - Should be advertising-api-eu.amazon.com
4. Response status - Should be 200, not 404
""")


if __name__ == "__main__":
    asyncio.run(test_tool_invocation())