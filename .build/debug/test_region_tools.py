#!/usr/bin/env python3
"""Test script for region management tools."""

import asyncio
import os
import sys

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from amazon_ads_mcp.tools.region import (
    get_active_region,
    list_available_regions,
    set_active_region
)


async def test_region_tools():
    """Test the region management tools."""
    print("=" * 60)
    print("Testing Region Management Tools")
    print("=" * 60)
    
    # Test listing available regions
    print("\n1. List available regions:")
    regions = await list_available_regions()
    if regions["success"]:
        print(f"   Current region: {regions['current_region']}")
        print(f"   Sandbox mode: {regions['sandbox_mode']}")
        print("\n   Available regions:")
        for region_code, region_info in regions["regions"].items():
            print(f"   - {region_code}: {region_info['name']}")
            print(f"     API: {region_info['api_endpoint']}")
            print(f"     OAuth: {region_info['oauth_endpoint']}")
    
    # Test getting current region
    print("\n2. Get current region:")
    current = await get_active_region()
    if current["success"]:
        print(f"   Region: {current['region']} ({current['region_name']})")
        print(f"   API endpoint: {current['api_endpoint']}")
        print(f"   Auth method: {current['auth_method']}")
        print(f"   Source: {current['source']}")
    
    # Test setting region (only if in test environment)
    if os.getenv("TEST_REGION_CHANGE") == "true":
        print("\n3. Test changing region:")
        
        # Try changing to EU
        print("   Changing to EU...")
        result = await set_active_region("eu")
        if result["success"]:
            print(f"   ✓ Changed from {result['previous_region']} to {result['new_region']}")
            print(f"   New endpoint: {result['api_endpoint']}")
        
        # Change back to original
        print(f"   Changing back to {current['region']}...")
        result = await set_active_region(current['region'])
        if result["success"]:
            print(f"   ✓ Restored to {result['new_region']}")
    else:
        print("\n3. Skipping region change test (set TEST_REGION_CHANGE=true to enable)")
    
    print("\n✅ Region tools test completed successfully!")


async def main():
    """Run the test."""
    try:
        await test_region_tools()
        return 0
    except Exception as e:
        print(f"\n❌ Error testing region tools: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)