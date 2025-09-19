#!/usr/bin/env python3
"""Test different regional endpoints for Amazon Ads API."""

import asyncio
import httpx
from dotenv import load_dotenv
from amazon_ads_mcp.config.settings import settings
from amazon_ads_mcp.utils.auth import AmazonAdsAuth

load_dotenv()


async def test_regional_endpoints():
    """Test all regional endpoints."""
    print("🌍 Testing Amazon Ads API Regional Endpoints")
    print("=" * 50)
    
    # Check current settings
    print(f"\nCurrent Settings:")
    print(f"  Region: {settings.amazon_ads_region}")
    print(f"  Configured Endpoint: {settings.region_endpoint}")
    
    # Initialize authentication
    auth = AmazonAdsAuth(
        client_id=settings.amazon_ads_client_id,
        client_secret=settings.amazon_ads_client_secret,
        refresh_token=settings.amazon_ads_refresh_token,
    )
    
    await auth.get_access_token()
    print("\n✅ Got access token")
    
    # All regional endpoints
    regional_endpoints = {
        "NA": {
            "url": "https://advertising-api.amazon.com",
            "marketplaces": ["US", "CA", "MX", "BR"]
        },
        "EU": {
            "url": "https://advertising-api-eu.amazon.com",
            "marketplaces": ["UK", "FR", "IT", "ES", "DE", "NL", "AE", "PL", "TR", "EG", "SA", "SE", "BE", "IN", "ZA"]
        },
        "FE": {
            "url": "https://advertising-api-fe.amazon.com",
            "marketplaces": ["JP", "AU", "SG"]
        }
    }
    
    headers = {
        "Amazon-Advertising-API-ClientId": settings.amazon_ads_client_id,
        "Authorization": f"Bearer {auth.access_token}",
        "Content-Type": "application/json",
    }
    
    print("\n🔧 Testing Each Regional Endpoint:")
    
    for region, config in regional_endpoints.items():
        print(f"\n{region} Region - {config['url']}")
        print(f"  Marketplaces: {', '.join(config['marketplaces'])}")
        
        async with httpx.AsyncClient(base_url=config['url'], timeout=10.0) as client:
            # Test profiles endpoint
            try:
                response = await client.get("/v2/profiles", headers=headers)
                print(f"  /v2/profiles: {response.status_code}")
                
                if response.status_code == 200:
                    profiles = response.json()
                    print(f"  ✅ Success! Found {len(profiles)} profiles")
                    if profiles:
                        print(f"  First profile country: {profiles[0].get('countryCode')}")
                elif response.status_code == 401:
                    print(f"  ❌ Unauthorized - API access not granted for this region")
                else:
                    print(f"  Response: {response.text[:100]}...")
                    
            except Exception as e:
                print(f"  Error: {e}")
            
            # Test test accounts endpoint
            try:
                response = await client.get("/testAccounts", headers=headers)
                print(f"  /testAccounts: {response.status_code}")
            except Exception as e:
                print(f"  Error: {e}")
    
    print("\n📌 Notes:")
    print("- Your refresh token is tied to a specific marketplace")
    print("- You need to use the correct regional endpoint for your account")
    print("- If you get 401 on all regions, your app needs API approval")
    print("- If you get 200 on one region, that's your correct endpoint")


if __name__ == "__main__":
    asyncio.run(test_regional_endpoints())