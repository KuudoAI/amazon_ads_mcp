#!/usr/bin/env python3
"""
Test EU routing via MCP server using correct endpoint and protocol.
"""

import asyncio
import json
import httpx


async def mcp_request(method: str, params: dict = None):
    """Make a JSON-RPC request to the MCP server."""
    url = "http://localhost:9080/mcp"
    
    async with httpx.AsyncClient() as client:
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
            "id": 1
        }
        
        print(f"\nRequest: {method}")
        print(f"Params: {json.dumps(params, indent=2) if params else '{}'}")
        
        response = await client.post(
            url,
            json=payload,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream"
            },
            timeout=30.0
        )
        
        print(f"Status: {response.status_code}")
        
        if response.status_code == 200:
            # Handle SSE or JSON response
            content_type = response.headers.get("content-type", "")
            
            if "text/event-stream" in content_type:
                # Parse SSE format
                lines = response.text.strip().split('\n')
                for line in lines:
                    if line.startswith("data: "):
                        try:
                            data = json.loads(line[6:])
                            if "error" in data:
                                print(f"Error: {data['error']}")
                            elif "result" in data:
                                print(f"Result: {json.dumps(data['result'], indent=2)[:500]}...")
                            return data
                        except json.JSONDecodeError:
                            continue
            else:
                # Regular JSON response
                try:
                    data = response.json()
                    if "error" in data:
                        print(f"Error: {data['error']}")
                    elif "result" in data:
                        print(f"Result: {json.dumps(data['result'], indent=2)[:500]}...")
                    return data
                except json.JSONDecodeError:
                    print(f"Failed to parse response: {response.text[:200]}")
                    return None
        else:
            print(f"HTTP Error: {response.text[:200]}")
            return None


async def main():
    print("="*80)
    print("MCP SERVER EU ROUTING TEST (Correct Protocol)")
    print("="*80)
    
    try:
        # 1. Initialize session
        print("\n1. Initializing MCP session...")
        await mcp_request("initialize", {
            "protocolVersion": "1.0.0",
            "capabilities": {},
            "clientInfo": {"name": "test-client", "version": "1.0"}
        })
        
        # 2. List available tools
        print("\n2. Listing available tools...")
        tools_response = await mcp_request("tools/list")
        
        if tools_response and "result" in tools_response:
            tools = tools_response["result"].get("tools", [])
            print(f"\nFound {len(tools)} tools")
            
            # Find the tools we need
            tool_names = [t.get("name") for t in tools]
            if "set_region_override" in tool_names:
                print("✅ Found set_region_override tool")
            if "ap_listProfiles" in tool_names:
                print("✅ Found ap_listProfiles tool")
            if "show_routing_state" in tool_names:
                print("✅ Found show_routing_state tool")
        
        # 3. Set region to EU
        print("\n3. Setting region override to EU...")
        result = await mcp_request("tools/call", {
            "name": "set_region_override",
            "arguments": {"region": "eu"}
        })
        
        # 4. Check routing state
        print("\n4. Checking routing state...")
        routing = await mcp_request("tools/call", {
            "name": "show_routing_state",
            "arguments": {}
        })
        
        if routing and "result" in routing:
            result = routing["result"]
            if isinstance(result, dict) and result.get("content"):
                # Parse the content if it's a string
                content = result.get("content", [])
                if content and isinstance(content[0], dict):
                    text = content[0].get("text", "")
                    if "advertising-api-eu.amazon.com" in text:
                        print("✅ EU endpoint correctly configured!")
                    else:
                        print(f"⚠️ Routing state: {text[:200]}")
        
        # 5. Try to list profiles with EU
        print("\n5. Calling ap_listProfiles (EU region)...")
        eu_result = await mcp_request("tools/call", {
            "name": "ap_listProfiles",
            "arguments": {}
        })
        
        eu_success = False
        if eu_result:
            if "error" in eu_result:
                error_msg = str(eu_result["error"])
                if "404" in error_msg:
                    print("❌ 404 error on EU endpoint - routing issue confirmed!")
                else:
                    print(f"❌ Error: {error_msg[:200]}")
            elif "result" in eu_result:
                print("✅ EU endpoint worked!")
                eu_success = True
        
        # 6. Clear override and test NA
        print("\n6. Clearing region override...")
        await mcp_request("tools/call", {
            "name": "clear_region_override",
            "arguments": {}
        })
        
        print("\n7. Calling ap_listProfiles (default/NA region)...")
        na_result = await mcp_request("tools/call", {
            "name": "ap_listProfiles",
            "arguments": {}
        })
        
        na_success = False
        if na_result:
            if "error" in na_result:
                error_msg = str(na_result["error"])
                print(f"❌ NA Error: {error_msg[:200]}")
            elif "result" in na_result:
                print("✅ NA endpoint worked!")
                na_success = True
        
        # Summary
        print("\n" + "="*80)
        print("DIAGNOSIS")
        print("="*80)
        
        if na_success and not eu_success:
            print("🔍 SMOKING GUN CONFIRMED!")
            print("   - NA endpoint: ✅ WORKS")
            print("   - EU endpoint: ❌ FAILS (404)")
            print("\nThis confirms the issue is NOT in your MCP server code.")
            print("The problem is with accessing the EU Amazon Ads API endpoint.")
            print("\nLikely causes:")
            print("1. Network/firewall blocking advertising-api-eu.amazon.com")
            print("2. DNS resolution issue for EU domain")
            print("3. Corporate proxy treating EU domain differently")
            print("4. Access token doesn't have EU marketplace scope")
        elif na_success and eu_success:
            print("✅ Both regions work via MCP!")
            print("Issue might be with upstream client (Claude Desktop)")
        elif not na_success and not eu_success:
            print("❌ Neither region works - check credentials/authentication")
        else:
            print("🤔 Unexpected result pattern")
        
    except httpx.ConnectError:
        print("❌ Cannot connect to MCP server at http://localhost:9080/mcp")
        print("   Please ensure the MCP server is running")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())