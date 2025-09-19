#!/usr/bin/env python3
"""
Simplified test to check EU routing via MCP server.
Tests the MCP server directly using JSON-RPC protocol.
"""

import asyncio
import json
import httpx


async def call_mcp_tool(tool_name: str, arguments: dict = None):
    """Call an MCP tool via JSON-RPC."""
    url = "http://localhost:9080"
    
    async with httpx.AsyncClient() as client:
        # MCP uses JSON-RPC protocol
        payload = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments or {}
            },
            "id": 1
        }
        
        response = await client.post(
            url,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=30.0
        )
        
        return response


async def main():
    print("="*80)
    print("MCP SERVER EU ROUTING TEST")
    print("="*80)
    
    try:
        # 1. Set region override to EU
        print("\n1. Setting region override to EU...")
        response = await call_mcp_tool("set_region_override", {"region": "eu"})
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"   Response: {json.dumps(data, indent=2)}")
        
        # 2. Check routing state
        print("\n2. Checking routing state...")
        response = await call_mcp_tool("show_routing_state")
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"   Response: {json.dumps(data, indent=2)}")
            
            # Check if EU is properly set
            if "result" in data:
                result = data.get("result", {})
                if isinstance(result, dict):
                    host = result.get("host", "")
                    region = result.get("region", "")
                    if "advertising-api-eu.amazon.com" in host:
                        print("   ✅ EU host correctly set!")
                    else:
                        print(f"   ❌ Wrong host: {host}")
        
        # 3. List profiles
        print("\n3. Calling ap_listProfiles (EU region)...")
        response = await call_mcp_tool("ap_listProfiles")
        print(f"   Status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            
            # Check for error in result
            if "error" in data:
                error = data["error"]
                print(f"   ❌ Error: {error}")
                
                # Check if it's a 404 error
                if "404" in str(error):
                    print("\n   🔍 SMOKING GUN: 404 error on EU endpoint!")
                    print("      This confirms EU routing issue, not MCP code issue.")
            elif "result" in data:
                result = data["result"]
                print(f"   ✅ Success! Got profiles data")
                print(f"   Preview: {str(result)[:200]}...")
        else:
            print(f"   ❌ HTTP Error: {response.status_code}")
            print(f"   Response: {response.text[:500]}")
        
        # 4. Clear override and test NA
        print("\n4. Clearing region override to test NA...")
        await call_mcp_tool("clear_region_override")
        
        print("\n5. Calling ap_listProfiles (default/NA region)...")
        response = await call_mcp_tool("ap_listProfiles")
        print(f"   Status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            if "error" in data:
                print(f"   ❌ Error: {data['error']}")
            elif "result" in data:
                print(f"   ✅ Success! NA endpoint works")
        
        # Summary
        print("\n" + "="*80)
        print("SUMMARY")
        print("="*80)
        print("If EU fails with 404 but NA works, this confirms:")
        print("1. Your MCP server code is correct")
        print("2. The issue is with EU endpoint access")
        print("3. Possible causes:")
        print("   - Network/firewall blocking EU domain")
        print("   - DNS issue with advertising-api-eu.amazon.com")
        print("   - Token doesn't have EU scope")
        
    except httpx.ConnectError:
        print("❌ Cannot connect to MCP server at http://localhost:9080")
        print("   Please ensure the MCP server is running")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")


if __name__ == "__main__":
    asyncio.run(main())