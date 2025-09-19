#!/usr/bin/env python3
"""Test auto-detection of working Amazon Ads identity."""

import asyncio
import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

# Set log level to see debug messages
os.environ["LOG_LEVEL"] = "DEBUG"

from amazon_ads_mcp.server.main import create_amazon_ads_server


async def test_auto_detect():
    """Test auto-detection of working identity."""
    print("🔍 Testing Auto-Detection of Amazon Ads Identity")
    print("=" * 50)
    
    try:
        print("\n1. Creating server with auto-detection...")
        mcp = await create_amazon_ads_server()
        
        print(f"\n✅ Server created successfully!")
        print(f"   Auto-detection found a working Amazon Ads identity")
        
        return True
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = asyncio.run(test_auto_detect())
    sys.exit(0 if success else 1)