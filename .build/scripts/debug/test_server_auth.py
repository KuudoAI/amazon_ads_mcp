#!/usr/bin/env python3
"""Test the server authentication setup."""

import asyncio
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from amazon_ads_mcp.server.main import create_amazon_ads_server


async def test_server():
    """Test creating the server with Openbridge auth."""
    print("🚀 Testing Server with Openbridge Authentication")
    print("=" * 50)
    
    try:
        # Create the server
        print("\n1. Creating server...")
        mcp = await create_amazon_ads_server()
        
        print(f"\n✅ Server created successfully!")
        print(f"   Name: {mcp.name}")
        
        # The server is a FastMCPOpenAPI instance
        print(f"   Type: {type(mcp).__name__}")
        
        return True
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = asyncio.run(test_server())
    sys.exit(0 if success else 1)