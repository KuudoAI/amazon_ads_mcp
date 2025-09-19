#!/usr/bin/env python3
"""
Simple direct test of the MCP server
"""

import asyncio
import json
from mcp import ClientSession
from mcp.client.stdio import stdio_client, StdioServerParameters
from dotenv import load_dotenv

load_dotenv()

async def test():
    server_params = StdioServerParameters(
        command=".venv/bin/python",
        args=["-m", "src.amazon_ads_mcp.server.mcp_server_mounted", "--transport", "stdio"],
        env=None
    )
    
    print("Starting server...")
    
    async with stdio_client(server_params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            print("Initializing...")
            await session.initialize()
            print("✓ Initialized")
            
            print("\nListing tools...")
            tools_response = await session.list_tools()
            
            # Check what type of response we got
            print(f"Tools response type: {type(tools_response)}")
            
            if hasattr(tools_response, '__dict__'):
                print(f"Tools response attributes: {tools_response.__dict__}")
            
            # Try to access tools
            if hasattr(tools_response, 'tools'):
                tools = tools_response.tools
                print(f"Found {len(tools)} tools")
                
                # Show first few tools
                for i, tool in enumerate(tools[:3]):
                    print(f"\nTool {i+1}:")
                    print(f"  Type: {type(tool)}")
                    if hasattr(tool, '__dict__'):
                        print(f"  Attributes: {tool.__dict__}")
                    if hasattr(tool, 'name'):
                        print(f"  Name: {tool.name}")
                    if hasattr(tool, 'description'):
                        print(f"  Description: {tool.description[:100]}...")
            else:
                print("No 'tools' attribute found")
            
            print("\n✓ Test complete")

if __name__ == "__main__":
    asyncio.run(test())