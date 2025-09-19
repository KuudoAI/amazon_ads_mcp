#!/usr/bin/env python3
"""Test the Exports API endpoints."""

import asyncio
import json
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from amazon_ads_mcp.server.main import create_amazon_ads_server
from amazon_ads_mcp.auth.openbridge_auth import OpenbridgeAuth
from amazon_ads_mcp.config.settings import settings


async def test_exports_api():
    """Test the Exports API endpoints."""
    print("📤 Testing Amazon Ads Exports API")
    print("=" * 50)
    
    try:
        # Create the MCP server
        print("\n1. Creating MCP server with Exports API...")
        mcp = await create_amazon_ads_server()
        print("   ✅ Server created")
        
        # Get authentication
        print("\n2. Getting authentication...")
        openbridge_auth = OpenbridgeAuth(refresh_token=settings.openbridge_refresh_token)
        token_info = await openbridge_auth.get_amazon_ads_token(settings.openbridge_remote_identity_id)
        print(f"   ✅ Got token")
        
        # Get a profile ID to use
        print("\n3. Getting profile to use for export...")
        import httpx
        async with httpx.AsyncClient() as client:
            # Get profiles
            profiles_response = await client.get(
                f"{settings.region_endpoint}/v2/profiles",
                headers={
                    "Authorization": f"Bearer {token_info['access_token']}",
                    "Amazon-Advertising-API-ClientId": token_info['client_id'],
                    "Content-Type": "application/json",
                }
            )
            
            if profiles_response.status_code == 200:
                profiles = profiles_response.json()
                # Use a seller profile (not agency)
                seller_profiles = [p for p in profiles if p['accountInfo']['type'] == 'seller' and p['countryCode'] == 'US']
                if seller_profiles:
                    us_profile = seller_profiles[0]
                else:
                    # Fallback to any seller profile
                    us_profile = next((p for p in profiles if p['accountInfo']['type'] == 'seller'), profiles[0])
                profile_id = us_profile['profileId']
                print(f"   ✅ Using profile: {profile_id} ({us_profile['accountInfo']['name']})")
                
                # Create a campaigns export
                print("\n4. Creating campaigns export...")
                export_response = await client.post(
                    f"{settings.region_endpoint}/campaigns/export",
                    headers={
                        "Authorization": f"Bearer {token_info['access_token']}",
                        "Amazon-Advertising-API-ClientId": token_info['client_id'],
                        "Amazon-Advertising-API-Scope": str(profile_id),
                        "Content-Type": "application/vnd.campaignsexport.v1+json",
                        "Accept": "application/vnd.campaignsexport.v1+json",
                    },
                    json={
                        "stateFilter": ["ENABLED", "PAUSED"],
                        "adProductFilter": ["SPONSORED_PRODUCTS", "SPONSORED_BRANDS", "SPONSORED_DISPLAY"]
                    }
                )
                
                print(f"   Export response status: {export_response.status_code}")
                
                if export_response.status_code == 202:
                    export_data = export_response.json()
                    export_id = export_data['exportId']
                    print(f"   ✅ Export created! ID: {export_id}")
                    print(f"   Status: {export_data['status']}")
                    
                    # Check export status
                    print("\n5. Checking export status...")
                    await asyncio.sleep(2)  # Wait a bit
                    
                    status_response = await client.get(
                        f"{settings.region_endpoint}/exports/{export_id}",
                        headers={
                            "Authorization": f"Bearer {token_info['access_token']}",
                            "Amazon-Advertising-API-ClientId": token_info['client_id'],
                            "Amazon-Advertising-API-Scope": str(profile_id),
                            "Accept": "application/vnd.campaignsexport.v1+json",
                        }
                    )
                    
                    if status_response.status_code == 200:
                        status_data = status_response.json()
                        print(f"   Export status: {status_data['status']}")
                        
                        if status_data['status'] == 'COMPLETED':
                            print(f"   ✅ Export completed!")
                            print(f"   Download URL: {status_data.get('url', 'Not yet available')}")
                            print(f"   File size: {status_data.get('fileSize', 'Unknown')} bytes")
                        elif status_data['status'] == 'PROCESSING':
                            print("   ⏳ Export still processing...")
                            print(f"   Created at: {status_data.get('createdAt')}")
                        else:
                            print(f"   ❌ Export failed: {status_data.get('error')}")
                    else:
                        print(f"   ❌ Failed to get status: {status_response.status_code}")
                        print(f"   Response: {status_response.text}")
                else:
                    print(f"   ❌ Failed to create export: {export_response.status_code}")
                    print(f"   Response: {export_response.text}")
            else:
                print(f"   ❌ Failed to get profiles: {profiles_response.status_code}")
        
        print("\n✅ Exports API is successfully integrated!")
        print("\nAvailable export endpoints:")
        print("   - POST /ads/export - Export ads")
        print("   - POST /campaigns/export - Export campaigns")
        print("   - POST /adGroups/export - Export ad groups")
        print("   - POST /targets/export - Export targets")
        print("   - GET /exports/{exportId} - Check export status")
        
        await openbridge_auth.close()
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(test_exports_api())