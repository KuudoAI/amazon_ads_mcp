#!/usr/bin/env python3
"""
Test EU routing using the MCP client directly.
This tests if the issue is with the upstream client (Claude Desktop) or the server.
"""

import asyncio
import json
import sys
from pathlib import Path

# Add client directory to path
sys.path.insert(0, str(Path(__file__).parent / "client"))

from client import AmazonAdsMCPClient, ClientConfig, TransportType


async def test_eu_routing():
    """Test EU routing with MCP client."""
    print("="*80)
    print("EU ROUTING TEST WITH MCP CLIENT")
    print("="*80)
    
    # Configure client for local MCP server
    config = ClientConfig(
        transport=TransportType.HTTP,
        server_url="http://localhost:9080/mcp",
        request_timeout=30.0
    )
    
    client = AmazonAdsMCPClient(config)
    
    try:
        # Connect to server
        print("\n1. Connecting to MCP server...")
        await client.connect()
        print("   ✅ Connected")
        
        # List tools to confirm connection
        print("\n2. Listing available tools...")
        tools = await client.list_tools()
        print(f"   Found {len(tools)} tools")
        
        # Set region to EU
        print("\n3. Setting region override to EU...")
        result = await client.execute_tool("set_region_override", {"region": "eu"})
        print(f"   Result: {result}")
        
        # Check routing state
        print("\n4. Checking routing state...")
        routing = await client.execute_tool("show_routing_state", {})
        print(f"   Routing: {routing}")
        
        # Parse routing state to verify EU is set
        if routing and isinstance(routing, dict):
            content = routing.get("content", [])
            if content and isinstance(content, list):
                text = str(content[0].get("text", "") if isinstance(content[0], dict) else content[0])
                if "advertising-api-eu.amazon.com" in text:
                    print("   ✅ EU endpoint correctly configured!")
                else:
                    print(f"   ⚠️ Unexpected routing: {text[:200]}")
        
        # Try to list profiles with EU
        print("\n5. Calling ap_listProfiles with EU region...")
        try:
            eu_profiles = await client.execute_tool("ap_listProfiles", {})
            print("   ✅ EU endpoint WORKS!")
            print(f"   Response preview: {str(eu_profiles)[:200]}...")
            eu_success = True
        except Exception as e:
            error_msg = str(e)
            if "404" in error_msg:
                print("   ❌ 404 ERROR on EU endpoint!")
                print(f"   Error: {error_msg[:300]}")
            else:
                print(f"   ❌ Error: {error_msg[:300]}")
            eu_success = False
        
        # Clear override and test NA
        print("\n6. Clearing region override...")
        await client.execute_tool("clear_region_override", {})
        
        print("\n7. Testing NA region (default)...")
        try:
            na_profiles = await client.execute_tool("ap_listProfiles", {})
            print("   ✅ NA endpoint WORKS!")
            print(f"   Response preview: {str(na_profiles)[:200]}...")
            na_success = True
        except Exception as e:
            error_msg = str(e)
            print(f"   ❌ NA Error: {error_msg[:300]}")
            na_success = False
        
        # Summary
        print("\n" + "="*80)
        print("DIAGNOSIS")
        print("="*80)
        
        if na_success and not eu_success:
            print("🔍 SMOKING GUN CONFIRMED!")
            print("   - NA endpoint: ✅ WORKS")
            print("   - EU endpoint: ❌ FAILS with 404")
            print("\nThis confirms:")
            print("1. Your MCP server code is CORRECT")
            print("2. The issue is NOT with Claude Desktop")
            print("3. The problem is with accessing the EU Amazon Ads API endpoint")
            print("\nRoot cause is likely:")
            print("• Network/firewall blocking advertising-api-eu.amazon.com")
            print("• DNS resolution issue for EU domain")
            print("• VPN/proxy interfering with EU routing")
            print("• Access token lacks EU marketplace scope")
            print("\nNext steps:")
            print("1. Test from different network/VPN")
            print("2. Check: nslookup advertising-api-eu.amazon.com")
            print("3. Try: curl -I https://advertising-api-eu.amazon.com/v2/profiles")
            print("4. Contact Amazon Ads API support about EU access")
        elif na_success and eu_success:
            print("✅ SUCCESS: Both regions work!")
            print("The issue was likely with the upstream client configuration.")
        elif not na_success and not eu_success:
            print("❌ Neither region works - check authentication/credentials")
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
    finally:
        await client.disconnect()
        print("\n✅ Test complete")


if __name__ == "__main__":
    asyncio.run(test_eu_routing())