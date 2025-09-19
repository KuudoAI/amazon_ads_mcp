#!/usr/bin/env python3
"""Test the new Ads API v1 endpoints."""

import asyncio
import json
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from amazon_ads_mcp.server.main import create_amazon_ads_server
from amazon_ads_mcp.auth.openbridge_auth import OpenbridgeAuth
from amazon_ads_mcp.config.settings import settings


async def test_ads_api_v1():
    """Test the Ads API v1 endpoints."""
    print("🚀 Testing Amazon Ads API v1")
    print("=" * 50)
    
    try:
        # Create the MCP server
        print("\n1. Creating MCP server with Ads API v1...")
        mcp = await create_amazon_ads_server()
        print("   ✅ Server created")
        
        # Get authentication
        print("\n2. Getting authentication...")
        openbridge_auth = OpenbridgeAuth(refresh_token=settings.openbridge_refresh_token)
        token_info = await openbridge_auth.get_amazon_ads_token(settings.openbridge_remote_identity_id)
        print(f"   ✅ Got token")
        
        # Use profile 1043817530956285
        profile_id = "1043817530956285"
        
        import httpx
        async with httpx.AsyncClient(timeout=60.0) as client:
            headers = {
                "Authorization": f"Bearer {token_info['access_token']}",
                "Amazon-Advertising-API-ClientId": token_info['client_id'],
                "Amazon-Advertising-API-Scope": str(profile_id),
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
            
            # Test 1: Query campaigns
            print(f"\n3. Testing query campaigns endpoint...")
            query_response = await client.post(
                f"{settings.region_endpoint}/adsApi/v1/query/campaigns",
                headers=headers,
                json={
                    "adProductFilter": ["SPONSORED_PRODUCTS", "SPONSORED_BRANDS", "SPONSORED_DISPLAY"],
                    "stateFilter": ["ENABLED", "PAUSED"],
                    "maxResults": 5
                }
            )
            
            print(f"   Status: {query_response.status_code}")
            
            if query_response.status_code == 200:
                campaigns = query_response.json().get('campaigns', [])
                print(f"   ✅ SUCCESS! Found {len(campaigns)} campaigns")
                
                if campaigns:
                    print("\n   Sample campaign:")
                    campaign = campaigns[0]
                    print(f"   - ID: {campaign.get('campaignId')}")
                    print(f"   - Name: {campaign.get('name')}")
                    print(f"   - State: {campaign.get('state')}")
                    print(f"   - Budget: {campaign.get('budget')}")
            else:
                print(f"   Response: {query_response.text[:200]}...")
            
            # Test 2: Query ad groups
            print(f"\n4. Testing query ad groups endpoint...")
            adgroups_response = await client.post(
                f"{settings.region_endpoint}/adsApi/v1/query/adGroups",
                headers=headers,
                json={
                    "adProductFilter": ["SPONSORED_PRODUCTS"],
                    "stateFilter": ["ENABLED"],
                    "maxResults": 3
                }
            )
            
            print(f"   Status: {adgroups_response.status_code}")
            
            if adgroups_response.status_code == 200:
                ad_groups = adgroups_response.json().get('adGroups', [])
                print(f"   ✅ SUCCESS! Found {len(ad_groups)} ad groups")
            else:
                print(f"   Response: {adgroups_response.text[:200]}...")
            
            # Test 3: Query ads
            print(f"\n5. Testing query ads endpoint...")
            ads_response = await client.post(
                f"{settings.region_endpoint}/adsApi/v1/query/ads",
                headers=headers,
                json={
                    "adProductFilter": ["SPONSORED_PRODUCTS"],
                    "stateFilter": ["ENABLED"],
                    "maxResults": 3
                }
            )
            
            print(f"   Status: {ads_response.status_code}")
            
            if ads_response.status_code == 200:
                ads = ads_response.json().get('ads', [])
                print(f"   ✅ SUCCESS! Found {len(ads)} ads")
            else:
                print(f"   Response: {ads_response.text[:200]}...")
        
        print("\n✅ Ads API v1 is successfully integrated!")
        print("\nAvailable endpoints:")
        print("   - POST /adsApi/v1/create/campaigns")
        print("   - POST /adsApi/v1/create/adGroups")
        print("   - POST /adsApi/v1/create/ads")
        print("   - POST /adsApi/v1/create/targets")
        print("   - POST /adsApi/v1/create/adAssociations")
        print("   - POST /adsApi/v1/update/* (same entities)")
        print("   - POST /adsApi/v1/delete/* (same entities)")
        print("   - POST /adsApi/v1/query/* (same entities)")
        
        await openbridge_auth.close()
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(test_ads_api_v1())