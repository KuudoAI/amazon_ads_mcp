#!/usr/bin/env python3
"""Test how FastMCP exposes tools."""

import asyncio
import logging
from amazon_ads_mcp.server.main_dynamic import create_dynamic_amazon_ads_server

logging.basicConfig(level=logging.INFO)

async def test_tools():
    """Test tool access in FastMCP."""
    try:
        # Create the server
        mcp = await create_dynamic_amazon_ads_server()
        print(f"Created MCP server: {mcp.name}")
        
        # Check different ways to access tools
        print("\n1. Checking mcp.get_tools():")
        try:
            # get_tools() is async
            tools = await mcp.get_tools()
            print(f"   Found {len(tools)} tools")
            if tools:
                first_tool = tools[0]
                print(f"   First tool type: {type(first_tool)}")
                if isinstance(first_tool, dict):
                    print(f"   First tool keys: {list(first_tool.keys())}")
                    print(f"   First tool: {first_tool}")
                else:
                    print(f"   First tool attributes: {[attr for attr in dir(first_tool) if not attr.startswith('_')]}")
                    if hasattr(first_tool, 'name'):
                        print(f"   First tool name: {first_tool.name}")
                    if hasattr(first_tool, 'description'):
                        print(f"   First tool description: {first_tool.description[:100]}...")
        except Exception as e:
            print(f"   Error: {e}")
            import traceback
            traceback.print_exc()
        
        print("\n2. Checking mcp.tools:")
        if hasattr(mcp, 'tools'):
            print(f"   mcp.tools exists: {type(mcp.tools)}")
            try:
                print(f"   Length: {len(mcp.tools)}")
            except:
                pass
        else:
            print("   mcp.tools does not exist")
        
        print("\n3. Checking mcp._tool_manager:")
        if hasattr(mcp, '_tool_manager'):
            print(f"   mcp._tool_manager exists: {type(mcp._tool_manager)}")
            if hasattr(mcp._tool_manager, 'tools'):
                print(f"   mcp._tool_manager.tools exists: {type(mcp._tool_manager.tools)}")
                try:
                    print(f"   Length: {len(mcp._tool_manager.tools)}")
                except:
                    pass
        else:
            print("   mcp._tool_manager does not exist")
        
        print("\n4. Checking dir(mcp):")
        tool_related = [attr for attr in dir(mcp) if 'tool' in attr.lower()]
        print(f"   Tool-related attributes: {tool_related}")
        
        print("\n5. Checking mcp.__dict__:")
        tool_keys = [k for k in mcp.__dict__.keys() if 'tool' in k.lower()]
        print(f"   Tool-related keys in __dict__: {tool_keys}")
        
    except Exception as e:
        print(f"Error creating server: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_tools())