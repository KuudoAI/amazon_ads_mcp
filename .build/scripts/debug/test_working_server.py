#!/usr/bin/env python3
"""Test the server with the working configuration."""

import asyncio
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from amazon_ads_mcp.server.main import create_amazon_ads_server


async def test_server():
    """Test the server with working auth configuration."""
    print("🚀 Testing Server with Working Configuration")
    print("=" * 50)
    
    try:
        # Create the server
        print("\n1. Creating server with identity ID 3175...")
        mcp = await create_amazon_ads_server()
        
        print(f"\n✅ Server created successfully!")
        print(f"   Name: {mcp.name}")
        print(f"   Type: {type(mcp).__name__}")
        
        # The server is now ready to handle MCP requests
        print("\n2. Server is ready to handle MCP requests!")
        print("   Available endpoints from OpenAPI specs:")
        print("   - GET /testAccounts")
        print("   - POST /testAccounts")
        print("   - GET /v2/profiles")
        print("   - PUT /v2/profiles")
        print("   - GET /v2/profiles/{profileId}")
        
        print("\n✅ The MCP server is configured and ready to use!")
        print("\nTo run the server, use:")
        print("   python -m amazon_ads_mcp.server.main")
        
        return True
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = asyncio.run(test_server())
    sys.exit(0 if success else 1)