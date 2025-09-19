#!/usr/bin/env python3
"""
Fix the mount issue by using as_proxy parameter.
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
from amazon_ads_mcp.server.mcp_server import AuthenticatedClient


async def test_proxy_mount():
    """Test mounting with as_proxy=True."""
    
    print("="*80)
    print("TESTING MOUNT WITH as_proxy=True")
    print("="*80)
    
    # Load the AccountsProfiles spec
    spec_path = Path("openapi/resources/AccountsProfiles.json")
    with open(spec_path) as f:
        spec = json.load(f)
    
    # Create base server
    base = FastMCP(name="test-base")
    
    # Create sub-server from OpenAPI
    auth_manager = AuthManager()
    await auth_manager.set_active_identity("12927")
    
    client = AuthenticatedClient(
        base_url="https://advertising-api-eu.amazon.com",
        auth_manager=auth_manager,
        timeout=30.0
    )
    
    sub = FastMCP.from_openapi(
        openapi_spec=spec,
        client=client,
        name="ap"
    )
    
    print(f"\n1. Sub-server has {len(sub._tool_manager._tools)} tools")
    
    # Try different mount approaches
    print("\n2. Testing different mount approaches:")
    
    # Approach 1: Default mount
    print("\n   a) Default mount (no parameters):")
    base1 = FastMCP(name="base1")
    base1.mount(server=sub, prefix="ap")
    print(f"      Base tools: {len(base1._tool_manager._tools)}")
    
    # Approach 2: Mount with as_proxy=True
    print("\n   b) Mount with as_proxy=True:")
    base2 = FastMCP(name="base2")
    base2.mount(server=sub, prefix="ap", as_proxy=True)
    print(f"      Base tools: {len(base2._tool_manager._tools)}")
    
    # Approach 3: Mount with as_proxy=False
    print("\n   c) Mount with as_proxy=False:")
    base3 = FastMCP(name="base3")
    base3.mount(server=sub, prefix="ap", as_proxy=False)
    print(f"      Base tools: {len(base3._tool_manager._tools)}")
    
    # Check the actual tool names
    for i, base_server in enumerate([base1, base2, base3], 1):
        tools = base_server._tool_manager._tools
        if tools:
            print(f"\n   Base{i} tools:")
            for name in list(tools.keys())[:3]:
                print(f"      - {name}")
    
    print("\n" + "="*80)
    print("RECOMMENDATION")
    print("="*80)
    
    # Check which approach worked
    if len(base2._tool_manager._tools) > 0:
        print("✅ Mount with as_proxy=True works!")
        print("   Update mcp_server.py line 933:")
        print("   FROM: base.mount(server=sub, prefix=prefix)")
        print("   TO:   base.mount(server=sub, prefix=prefix, as_proxy=True)")
    elif len(base3._tool_manager._tools) > 0:
        print("✅ Mount with as_proxy=False works!")
        print("   Update mcp_server.py line 933:")
        print("   FROM: base.mount(server=sub, prefix=prefix)")
        print("   TO:   base.mount(server=sub, prefix=prefix, as_proxy=False)")
    else:
        print("❌ Neither approach worked. Need to investigate further.")


if __name__ == "__main__":
    asyncio.run(test_proxy_mount())