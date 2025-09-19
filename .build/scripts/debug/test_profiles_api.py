#!/usr/bin/env python3
"""Test the Profiles API endpoints."""

import asyncio
import json
import httpx
from dotenv import load_dotenv
from amazon_ads_mcp.config.settings import settings
from amazon_ads_mcp.utils.auth import AmazonAdsAuth

load_dotenv()


async def test_profiles_api():
    """Test the Profiles API endpoints."""
    print("🚀 Testing Amazon Ads Profiles API")
    print("=" * 50)
    
    # Initialize authentication
    auth = AmazonAdsAuth(
        client_id=settings.amazon_ads_client_id,
        client_secret=settings.amazon_ads_client_secret,
        refresh_token=settings.amazon_ads_refresh_token,
    )
    
    await auth.get_access_token()
    print("✅ Got access token")
    
    # Create HTTP client
    client = httpx.AsyncClient(
        base_url=settings.region_endpoint,
        headers={
            "Amazon-Advertising-API-ClientId": settings.amazon_ads_client_id,
            "Authorization": f"Bearer {auth.access_token}",
            "Content-Type": "application/json",
        },
        timeout=30.0,
    )
    
    print("\n🔧 Testing Profiles API:")
    
    # 1. Get all profiles
    print("\n1. Getting all profiles (GET /v2/profiles)...")
    try:
        response = await client.get("/v2/profiles")
        print(f"   Status: {response.status_code}")
        
        if response.status_code == 200:
            profiles = response.json()
            print(f"   ✅ Found {len(profiles)} profiles")
            
            if profiles:
                print("\n   First profile:")
                profile = profiles[0]
                print(f"   - Profile ID: {profile.get('profileId')}")
                print(f"   - Country: {profile.get('countryCode')}")
                print(f"   - Currency: {profile.get('currencyCode')}")
                print(f"   - Timezone: {profile.get('timezone')}")
                print(f"   - Account Info: {profile.get('accountInfo')}")
                
                # 2. Get specific profile
                profile_id = profile.get('profileId')
                if profile_id:
                    print(f"\n2. Getting specific profile (GET /v2/profiles/{profile_id})...")
                    response = await client.get(f"/v2/profiles/{profile_id}")
                    print(f"   Status: {response.status_code}")
                    if response.status_code == 200:
                        print(f"   ✅ Successfully retrieved profile details")
                    else:
                        print(f"   Response: {response.text}")
                        
        else:
            print(f"   Response: {response.text}")
            
    except Exception as e:
        print(f"   Error: {e}")
    
    # 3. Test with query parameters
    print("\n3. Testing with query parameters...")
    query_params = [
        {"apiProgram": "campaign"},
        {"apiProgram": "billing"},
        {"accessLevel": "view"},
    ]
    
    for params in query_params:
        print(f"\n   Testing with {params}:")
        try:
            response = await client.get("/v2/profiles", params=params)
            print(f"   Status: {response.status_code}")
            if response.status_code == 200:
                profiles = response.json()
                print(f"   Found {len(profiles)} profiles")
        except Exception as e:
            print(f"   Error: {e}")
    
    await client.aclose()
    print("\n✅ Test complete!")


if __name__ == "__main__":
    asyncio.run(test_profiles_api())