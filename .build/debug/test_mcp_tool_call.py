#!/usr/bin/env python3
"""
Test calling MCP tools to debug 404 issue.
"""

import asyncio
import os
import sys
from pathlib import Path
import json

# Add project to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

# Set environment
os.environ["LOG_LEVEL"] = "DEBUG"
os.environ["OPENBRIDGE_REMOTE_IDENTITY_ID"] = "12927"

from amazon_ads_mcp.server.mcp_server import create_amazon_ads_server


async def test_mcp_tool_call():
    """Test calling an MCP tool to see if region routing works."""
    
    print("="*80)
    print("TESTING MCP TOOL CALL FOR EU PROFILE")
    print("="*80)
    
    # Create the server
    print("\n1. Creating Amazon Ads MCP server...")
    server = await create_amazon_ads_server()
    
    # Simulate what happens when Claude calls a tool
    print("\n2. Simulating MCP tool call for profile 3433820656974170...")
    print("   This is what happens when Claude calls ap_getProfile")
    print("-" * 40)
    
    try:
        # The tool call would come in as a request to call "ap_getProfile"
        # with profileId parameter
        
        # First check if the tool exists
        if hasattr(server, '_tool_manager') and hasattr(server._tool_manager, '_tools'):
            tools = server._tool_manager._tools
            print(f"\nAvailable tools: {len(tools)}")
            
            # Look for profile-related tools
            profile_tools = [name for name in tools.keys() if 'profile' in name.lower()]
            print(f"Profile tools: {profile_tools}")
            
            # Try to find the getProfile tool
            get_profile_tool = None
            for tool_name in tools.keys():
                if 'getprofile' in tool_name.lower():
                    get_profile_tool = tool_name
                    break
            
            if get_profile_tool:
                print(f"\nFound tool: {get_profile_tool}")
                
                # Get the tool function
                tool_func = tools[get_profile_tool]
                
                # Create a mock context
                class MockContext:
                    pass
                
                ctx = MockContext()
                
                # Call the tool with the profile ID
                print(f"\nCalling {get_profile_tool} with profileId=3433820656974170...")
                result = await tool_func(ctx, profileId="3433820656974170")
                
                print("-" * 40)
                print(f"\n3. Tool result:")
                print(json.dumps(result, indent=2)[:500])
                
            else:
                # The tools might be registered differently
                # Let's try to call through the server's call_tool method
                print("\nTrying server.call_tool method...")
                
                # Try different possible tool names
                tool_names = ["ap_getProfile", "ap_get_profile", "getProfile"]
                
                for tool_name in tool_names:
                    try:
                        print(f"\nTrying tool name: {tool_name}")
                        result = await server.call_tool(
                            tool_name,
                            {"profileId": "3433820656974170"}
                        )
                        print(f"Success! Result: {json.dumps(result, indent=2)[:500]}")
                        break
                    except Exception as e:
                        print(f"  Failed: {e}")
                
        else:
            print("❌ Could not access tool manager")
            
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n" + "="*80)
    print("ANALYSIS")
    print("="*80)
    print("""
If this fails with 404, the issue is in how FastMCP makes requests.
Check the debug logs for:
1. Whether region routing happens
2. Whether headers are injected
3. What the final URL is
""")


if __name__ == "__main__":
    asyncio.run(test_mcp_tool_call())