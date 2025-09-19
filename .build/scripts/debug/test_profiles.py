#!/usr/bin/env python3
"""Test getting Amazon Ads profiles first."""

import asyncio
import json
import httpx
from dotenv import load_dotenv
from amazon_ads_mcp.config.settings import settings
from amazon_ads_mcp.utils.auth import AmazonAdsAuth

load_dotenv()


async def test_profiles():
    """Test getting advertising profiles."""
    print("🚀 Testing Amazon Ads Profile Access")
    print("=" * 50)
    
    # Initialize authentication
    auth = AmazonAdsAuth(
        client_id=settings.amazon_ads_client_id,
        client_secret=settings.amazon_ads_client_secret,
        refresh_token=settings.amazon_ads_refresh_token,
    )
    
    # Get access token
    await auth.get_access_token()
    print("✅ Got access token")
    
    # Create HTTP client
    client = httpx.AsyncClient(
        base_url=settings.region_endpoint,
        headers=auth.get_auth_headers(),
        timeout=30.0,
    )
    
    print("\n🔧 Testing API Access:")
    
    # Try to get profiles (this is usually the first API call)
    print("\n1. Getting advertising profiles...")
    try:
        response = await client.get("/v2/profiles")
        print(f"   Status: {response.status_code}")
        print(f"   Headers: {dict(response.headers)}")
        
        if response.status_code == 200:
            profiles = response.json()
            print(f"   Found {len(profiles)} profiles")
            
            if profiles:
                print("\n   Profiles:")
                for profile in profiles[:3]:  # Show first 3
                    print(f"   - Profile ID: {profile.get('profileId')}")
                    print(f"     Country: {profile.get('countryCode')}")
                    print(f"     Type: {profile.get('accountInfo', {}).get('type')}")
                    print()
                
                # Use the first profile for subsequent calls
                if profiles[0].get('profileId'):
                    profile_id = str(profiles[0]['profileId'])
                    print(f"\n2. Testing with Profile ID: {profile_id}")
                    
                    # Update headers with profile ID
                    headers = auth.get_auth_headers(profile_id=profile_id)
                    client.headers.update(headers)
                    
                    # Try test account API with profile
                    response = await client.get("/testAccounts")
                    print(f"   Test Accounts Status: {response.status_code}")
                    if response.status_code == 200:
                        print(f"   Response: {response.json()}")
                    else:
                        print(f"   Response: {response.text}")
        else:
            print(f"   Response: {response.text}")
            
            # Try different API versions
            print("\n3. Trying different API endpoints...")
            
            # Try v3 profiles
            response = await client.get("/v3/profiles")
            print(f"   V3 Profiles Status: {response.status_code}")
            
            # Try SP (Sponsored Products) endpoint
            response = await client.get("/sp/profiles")
            print(f"   SP Profiles Status: {response.status_code}")
            
    except Exception as e:
        print(f"   Error: {e}")
    
    await client.aclose()
    print("\n✅ Test complete!")


if __name__ == "__main__":
    asyncio.run(test_profiles())