#!/usr/bin/env python3
"""Test with all possible header combinations."""

import asyncio
import httpx
from dotenv import load_dotenv
from amazon_ads_mcp.config.settings import settings
from amazon_ads_mcp.utils.auth import AmazonAdsAuth

load_dotenv()


async def test_all_headers():
    """Test with various header combinations."""
    print("🔍 Testing All Header Combinations")
    print("=" * 50)
    
    # Initialize authentication
    auth = AmazonAdsAuth(
        client_id=settings.amazon_ads_client_id,
        client_secret=settings.amazon_ads_client_secret,
        refresh_token=settings.amazon_ads_refresh_token,
    )
    
    await auth.get_access_token()
    print("✅ Got access token\n")
    
    # Base headers that are always required
    base_headers = {
        "Amazon-Advertising-API-ClientId": settings.amazon_ads_client_id,
        "Authorization": f"Bearer {auth.access_token}",
    }
    
    # Additional headers to test
    header_combinations = [
        {
            "name": "Minimal (only required)",
            "headers": base_headers
        },
        {
            "name": "With Content-Type",
            "headers": {
                **base_headers,
                "Content-Type": "application/json",
            }
        },
        {
            "name": "With Accept",
            "headers": {
                **base_headers,
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
        },
        {
            "name": "With User-Agent",
            "headers": {
                **base_headers,
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "amazon-ads-mcp/1.0",
            }
        },
        {
            "name": "With Amazon-Advertising-API-MarketplaceId",
            "headers": {
                **base_headers,
                "Content-Type": "application/json",
                "Amazon-Advertising-API-MarketplaceId": "ATVPDKIKX0DER",  # US marketplace
            }
        },
        {
            "name": "With X-Amz-Date",
            "headers": {
                **base_headers,
                "Content-Type": "application/json",
                "X-Amz-Date": "20250804T000000Z",
            }
        },
    ]
    
    async with httpx.AsyncClient(base_url=settings.region_endpoint, timeout=10.0) as client:
        for combo in header_combinations:
            print(f"{combo['name']}:")
            print("  Headers:")
            for k, v in combo['headers'].items():
                if k == "Authorization":
                    print(f"    {k}: Bearer ***")
                else:
                    print(f"    {k}: {v}")
            
            try:
                response = await client.get("/v2/profiles", headers=combo['headers'])
                print(f"  Response: {response.status_code}")
                
                if response.status_code != 401:
                    print(f"  ✅ Different response! Body: {response.text[:100]}...")
                    
            except Exception as e:
                print(f"  Error: {e}")
            
            print()
    
    print("\n📌 Conclusion:")
    print("If all combinations return 401, the issue is definitely with API access permissions.")
    print("The app needs to be registered and approved at https://advertising.amazon.com/API/")


if __name__ == "__main__":
    asyncio.run(test_all_headers())