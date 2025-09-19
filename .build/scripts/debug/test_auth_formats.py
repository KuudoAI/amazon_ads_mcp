#!/usr/bin/env python3
"""Test different authorization header formats."""

import asyncio
import httpx
from dotenv import load_dotenv
from amazon_ads_mcp.config.settings import settings
from amazon_ads_mcp.utils.auth import AmazonAdsAuth

load_dotenv()


async def test_auth_formats():
    """Test different authorization header formats."""
    print("🔍 Testing Authorization Header Formats")
    print("=" * 50)
    
    # Initialize authentication
    auth = AmazonAdsAuth(
        client_id=settings.amazon_ads_client_id,
        client_secret=settings.amazon_ads_client_secret,
        refresh_token=settings.amazon_ads_refresh_token,
    )
    
    await auth.get_access_token()
    print("✅ Got access token")
    print(f"   Token prefix: {auth.access_token[:20]}...")
    
    client = httpx.AsyncClient(
        base_url=settings.region_endpoint,
        timeout=30.0,
    )
    
    # Different authorization formats to test
    auth_formats = [
        {
            "name": "Standard Bearer Token",
            "headers": {
                "Authorization": f"Bearer {auth.access_token}",
                "Amazon-Advertising-API-ClientId": settings.amazon_ads_client_id,
                "Content-Type": "application/json",
            }
        },
        {
            "name": "Without Bearer prefix",
            "headers": {
                "Authorization": auth.access_token,
                "Amazon-Advertising-API-ClientId": settings.amazon_ads_client_id,
                "Content-Type": "application/json",
            }
        },
        {
            "name": "With X-Amz headers",
            "headers": {
                "Authorization": f"Bearer {auth.access_token}",
                "Amazon-Advertising-API-ClientId": settings.amazon_ads_client_id,
                "Content-Type": "application/json",
                "X-Amz-Access-Token": auth.access_token,
            }
        },
        {
            "name": "With Accept header",
            "headers": {
                "Authorization": f"Bearer {auth.access_token}",
                "Amazon-Advertising-API-ClientId": settings.amazon_ads_client_id,
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
        }
    ]
    
    # Test each format
    for format_config in auth_formats:
        print(f"\n{format_config['name']}:")
        
        try:
            # Test profiles endpoint
            response = await client.get("/v2/profiles", headers=format_config["headers"])
            print(f"   /v2/profiles: {response.status_code}")
            
            # Test accounts endpoint
            response = await client.get("/testAccounts", headers=format_config["headers"])
            print(f"   /testAccounts: {response.status_code}")
            
            if response.status_code == 200:
                print("   ✅ This format works!")
                break
            elif response.status_code != 401:
                print(f"   Response: {response.text[:100]}...")
                
        except Exception as e:
            print(f"   Error: {e}")
    
    # Test if we need to register the app first
    print("\n\nℹ️  Important Notes:")
    print("1. Amazon Ads API requires app registration and approval")
    print("2. You need an active Amazon Advertising account")
    print("3. The app must be approved for production access")
    print("4. Test/Sandbox access may require separate approval")
    print("\nTo check your app status:")
    print("   Visit: https://advertising.amazon.com/API/cm/applications")
    
    await client.aclose()


if __name__ == "__main__":
    asyncio.run(test_auth_formats())