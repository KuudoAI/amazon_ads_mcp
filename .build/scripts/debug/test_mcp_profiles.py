#!/usr/bin/env python3
"""Test calling the MCP server to get profiles."""

import asyncio
import json
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from amazon_ads_mcp.server.main import create_amazon_ads_server
from amazon_ads_mcp.auth.openbridge_auth import OpenbridgeAuth
from amazon_ads_mcp.config.settings import settings


async def test_mcp_profiles():
    """Test calling the MCP server's profiles endpoint."""
    print("📊 Testing MCP Server - Get Profiles")
    print("=" * 50)
    
    try:
        # Create the MCP server
        print("\n1. Creating MCP server...")
        mcp = await create_amazon_ads_server()
        print("   ✅ Server created")
        
        # The MCP server wraps the HTTP client, so we need to make a direct call
        # through the underlying client to test it
        print("\n2. Getting Amazon Ads token via Openbridge...")
        openbridge_auth = OpenbridgeAuth(refresh_token=settings.openbridge_refresh_token)
        token_info = await openbridge_auth.get_amazon_ads_token(settings.openbridge_remote_identity_id)
        print(f"   ✅ Got token for client: {token_info['client_id']}")
        
        # Make direct API call to test
        print("\n3. Calling /v2/profiles endpoint...")
        import httpx
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{settings.region_endpoint}/v2/profiles",
                headers={
                    "Authorization": f"Bearer {token_info['access_token']}",
                    "Amazon-Advertising-API-ClientId": token_info['client_id'],
                    "Content-Type": "application/json",
                }
            )
            
            if response.status_code == 200:
                profiles = response.json()
                print(f"\n✅ SUCCESS! Retrieved {len(profiles)} profiles\n")
                
                # Display all profiles
                for i, profile in enumerate(profiles, 1):
                    print(f"Profile {i}:")
                    print(f"  Profile ID: {profile.get('profileId')}")
                    print(f"  Country: {profile.get('countryCode')}")
                    print(f"  Currency: {profile.get('currencyCode')}")
                    print(f"  Timezone: {profile.get('timezone')}")
                    print(f"  Daily Budget: {profile.get('dailyBudget')}")
                    
                    account_info = profile.get('accountInfo', {})
                    print(f"  Account Info:")
                    print(f"    - Type: {account_info.get('type')}")
                    print(f"    - Name: {account_info.get('name')}")
                    print(f"    - ID: {account_info.get('id')}")
                    print(f"    - Marketplace: {account_info.get('marketplaceStringId')}")
                    print(f"    - Valid Payment: {account_info.get('validPaymentMethod')}")
                    print()
                
                # Also save to file for reference
                with open('profiles_output.json', 'w') as f:
                    json.dump(profiles, f, indent=2)
                print(f"Full response saved to: profiles_output.json")
                
            else:
                print(f"\n❌ Failed to get profiles: {response.status_code}")
                print(f"Response: {response.text}")
        
        await openbridge_auth.close()
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(test_mcp_profiles())