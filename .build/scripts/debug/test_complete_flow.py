#!/usr/bin/env python3
"""Test the complete Amazon Ads API flow as documented."""

import asyncio
import json
import httpx
from dotenv import load_dotenv
from amazon_ads_mcp.config.settings import settings
from amazon_ads_mcp.utils.auth import AmazonAdsAuth

load_dotenv()


async def test_complete_flow():
    """Test the complete flow for Amazon Ads API."""
    print("🚀 Testing Complete Amazon Ads API Flow")
    print("=" * 50)
    
    # Initialize authentication
    auth = AmazonAdsAuth(
        client_id=settings.amazon_ads_client_id,
        client_secret=settings.amazon_ads_client_secret,
        refresh_token=settings.amazon_ads_refresh_token,
    )
    
    print("\n1. Getting Access Token...")
    await auth.get_access_token()
    print("   ✅ Got access token")
    
    # Create base headers
    base_headers = {
        "Amazon-Advertising-API-ClientId": settings.amazon_ads_client_id,
        "Authorization": f"Bearer {auth.access_token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    
    print("\n2. Testing Without Profile Scope...")
    print("   (This is the initial call to get available profiles)")
    
    async with httpx.AsyncClient(base_url=settings.region_endpoint, timeout=30.0) as client:
        # First, try to get profiles without scope header
        try:
            response = await client.get("/v2/profiles", headers=base_headers)
            print(f"   Status: {response.status_code}")
            print(f"   Headers sent:")
            for k, v in base_headers.items():
                if k == "Authorization":
                    print(f"     {k}: Bearer ***")
                else:
                    print(f"     {k}: {v}")
            
            if response.status_code == 200:
                profiles = response.json()
                print(f"\n   ✅ Success! Found {len(profiles)} profiles:")
                
                for i, profile in enumerate(profiles[:3]):  # Show first 3
                    print(f"\n   Profile {i+1}:")
                    print(f"     Profile ID: {profile.get('profileId')}")
                    print(f"     Country Code: {profile.get('countryCode')}")
                    print(f"     Currency: {profile.get('currencyCode')}")
                    print(f"     Account Type: {profile.get('accountInfo', {}).get('type')}")
                    print(f"     Marketplace ID: {profile.get('accountInfo', {}).get('marketplaceStringId')}")
                
                # Now test with profile scope
                if profiles:
                    profile_id = str(profiles[0]['profileId'])
                    print(f"\n3. Testing With Profile Scope (Profile ID: {profile_id})...")
                    
                    scoped_headers = {
                        **base_headers,
                        "Amazon-Advertising-API-Scope": profile_id
                    }
                    
                    # Test various endpoints with profile scope
                    endpoints_to_test = [
                        "/v2/profiles",
                        f"/v2/profiles/{profile_id}",
                        "/v2/campaigns",
                        "/v2/adGroups",
                    ]
                    
                    for endpoint in endpoints_to_test:
                        try:
                            response = await client.get(endpoint, headers=scoped_headers)
                            print(f"   {endpoint}: {response.status_code}")
                        except Exception as e:
                            print(f"   {endpoint}: Error - {e}")
                            
            else:
                print(f"\n   ❌ Failed to retrieve profiles")
                print(f"   Response: {response.text}")
                
                # Check response headers for clues
                print("\n   Response Headers:")
                for k, v in response.headers.items():
                    if k.lower() in ['x-amzn-requestid', 'x-amz-rid', 'x-amzn-errortype']:
                        print(f"     {k}: {v}")
                
        except Exception as e:
            print(f"   Error: {e}")
    
    print("\n\n📋 Summary:")
    print("According to Amazon Ads API documentation:")
    print("1. First call /v2/profiles WITHOUT Amazon-Advertising-API-Scope header")
    print("2. This returns all profiles accessible to your account")
    print("3. Then use a profileId as Amazon-Advertising-API-Scope for subsequent calls")
    print("\nIf you're getting 401 errors:")
    print("- Your app needs to be registered at https://advertising.amazon.com/API/")
    print("- You need an active Amazon Advertising account")
    print("- The app must be approved for production access")
    print("- Check that your OAuth scope included 'advertising::campaign_management'")


if __name__ == "__main__":
    asyncio.run(test_complete_flow())