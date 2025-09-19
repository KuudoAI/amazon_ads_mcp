#!/usr/bin/env python3
"""
Test FastMCP mount issue - tools not being exposed.
"""

import asyncio
import os
import sys
from pathlib import Path
import json

# Add project to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

os.environ["OPENBRIDGE_REMOTE_IDENTITY_ID"] = "12927"

from fastmcp import FastMCP
from amazon_ads_mcp.auth.manager import AuthManager
from amazon_ads_mcp.utils.http_client import AuthenticatedClient
import httpx


async def test_mount():
    """Test mounting and tool exposure."""
    
    print("="*80)
    print("TESTING FASTMCP MOUNT BEHAVIOR")
    print("="*80)
    
    # Load the AccountsProfiles spec
    spec_path = Path("openapi/resources/AccountsProfiles.json")
    with open(spec_path) as f:
        spec = json.load(f)
    
    print(f"\n1. Loaded OpenAPI spec: {spec['info']['title']}")
    print(f"   Operations: {len(spec.get('paths', {}))}")
    
    # Create base server
    base = FastMCP(name="test-base")
    print(f"\n2. Created base server")
    print(f"   Base tools before mount: {len(base._tool_manager._tools if hasattr(base, '_tool_manager') else {})}")
    
    # Create sub-server from OpenAPI
    auth_manager = AuthManager()
    await auth_manager.set_active_identity("12927")
    
    client = AuthenticatedClient(
        base_url="https://advertising-api-eu.amazon.com",
        auth_manager=auth_manager,
        timeout=30.0
    )
    
    print(f"\n3. Creating sub-server from OpenAPI...")
    sub = FastMCP.from_openapi(
        openapi_spec=spec,
        client=client,
        name="ap"
    )
    
    # Check tools in sub-server
    sub_tools = sub._tool_manager._tools if hasattr(sub, '_tool_manager') else {}
    print(f"   Sub-server tools: {len(sub_tools)}")
    for tool_name in list(sub_tools.keys())[:5]:
        print(f"     - {tool_name}")
    
    # Mount the sub-server
    print(f"\n4. Mounting sub-server with prefix 'ap'...")
    base.mount(server=sub, prefix="ap")
    
    # Check tools in base after mount
    base_tools = base._tool_manager._tools if hasattr(base, '_tool_manager') else {}
    print(f"\n5. Base tools after mount: {len(base_tools)}")
    
    # Look for prefixed tools
    prefixed_tools = [name for name in base_tools.keys() if name.startswith("ap")]
    print(f"   Tools with 'ap' prefix: {len(prefixed_tools)}")
    for tool_name in prefixed_tools[:5]:
        print(f"     - {tool_name}")
    
    # Try to list tools through the API
    print(f"\n6. Listing tools through list_tools()...")
    try:
        from mcp.types import ListToolsResult
        # Simulate what happens when a client lists tools
        result = await base._mcp_list_tools()
        print(f"   Tools from list_tools(): {len(result.tools)}")
        for tool in result.tools[:5]:
            print(f"     - {tool.name}: {tool.description[:50]}...")
    except Exception as e:
        print(f"   Error: {e}")
    
    print("\n" + "="*80)
    print("ANALYSIS")
    print("="*80)
    print("""
If mounted tools are not exposed, possible issues:
1. FastMCP version incompatibility
2. Mount method not propagating tools correctly
3. Tool separator/prefix configuration issue
4. as_proxy parameter needed for mount
""")


if __name__ == "__main__":
    asyncio.run(test_mount())