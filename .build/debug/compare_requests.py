#!/usr/bin/env python3
"""
Compare direct AuthenticatedClient request vs FastMCP tool call.
"""

import asyncio
import os
import sys
from pathlib import Path

# Add project to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

# Set environment
os.environ["LOG_LEVEL"] = "DEBUG"
os.environ["OPENBRIDGE_REMOTE_IDENTITY_ID"] = "12927"

from amazon_ads_mcp.server.mcp_server import AuthenticatedClient, create_amazon_ads_server
from amazon_ads_mcp.auth.manager import AuthManager


async def test_direct():
    """Test direct request with AuthenticatedClient."""
    print("\n" + "="*60)
    print("DIRECT REQUEST (AuthenticatedClient)")
    print("="*60)
    
    auth_manager = AuthManager()
    await auth_manager.set_active_identity("12927")
    
    client = AuthenticatedClient(
        base_url="https://advertising-api-eu.amazon.com",
        auth_manager=auth_manager,
        timeout=30.0
    )
    
    try:
        response = await client.get("/v2/profiles/3433820656974170")
        print(f"✅ Status: {response.status_code}")
        print(f"   Content-Type: {response.headers.get('content-type')}")
        if response.status_code == 200:
            data = response.json()
            print(f"   Profile: {data.get('profileId')} - {data.get('countryCode')}")
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        await client.aclose()


async def test_fastmcp():
    """Test through FastMCP tool call."""
    print("\n" + "="*60)
    print("FASTMCP TOOL CALL")
    print("="*60)
    
    server = await create_amazon_ads_server()
    
    # Find the tool
    tools = await server._mcp_list_tools()
    get_profile_tool = None
    for tool in tools:
        if 'getprofile' in tool.name.lower() and 'ap_' in tool.name.lower():
            get_profile_tool = tool
            break
    
    if get_profile_tool:
        try:
            result = await server._mcp_call_tool(
                key=get_profile_tool.name,
                arguments={"profileId": "3433820656974170"}
            )
            print(f"✅ Tool result: {result}")
        except Exception as e:
            print(f"❌ Error: {e}")
    else:
        print("❌ Tool not found")


async def main():
    """Run both tests."""
    print("\nCOMPARING DIRECT vs FASTMCP REQUESTS")
    print("Testing profile 3433820656974170 in EU region")
    
    await test_direct()
    await test_fastmcp()
    
    print("\n" + "="*60)
    print("ANALYSIS")
    print("="*60)
    print("""
If direct works but FastMCP fails:
- FastMCP may be modifying headers
- FastMCP may be using a different HTTP client configuration
- FastMCP may be interfering with the request in some way
""")


if __name__ == "__main__":
    asyncio.run(main())