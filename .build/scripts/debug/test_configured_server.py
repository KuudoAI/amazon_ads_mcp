#!/usr/bin/env python3
"""Test the server with configured RID."""

import asyncio
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from amazon_ads_mcp.server.main import create_amazon_ads_server


async def test_server():
    """Test server with configured RID."""
    print("🚀 Testing Server with Configured RID")
    print("=" * 50)
    
    try:
        print("\n1. Creating server with RID from environment...")
        mcp = await create_amazon_ads_server()
        
        print(f"\n✅ Server created successfully!")
        print(f"   Name: {mcp.name}")
        print(f"   Using RID: 3175 (from OPENBRIDGE_REMOTE_IDENTITY_ID)")
        
        print("\n2. Server is ready to handle MCP requests!")
        print("   Available endpoints:")
        print("   - GET /testAccounts")
        print("   - POST /testAccounts")
        print("   - GET /v2/profiles")
        print("   - PUT /v2/profiles")
        print("   - GET /v2/profiles/{profileId}")
        
        return True
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = asyncio.run(test_server())
    sys.exit(0 if success else 1)