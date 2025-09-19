#!/usr/bin/env python3
"""Test various configurations for the Test Account API."""

import asyncio
import httpx
from dotenv import load_dotenv
from amazon_ads_mcp.config.settings import settings

load_dotenv()


async def test_variations():
    """Test different API configurations."""
    print("🔍 Testing Test Account API Variations")
    print("=" * 50)
    
    # Different base URLs to try
    base_urls = [
        "https://advertising-api.amazon.com",
        "https://advertising-api-test.amazon.com",
        "https://api.amazon.com",
    ]
    
    # Different header combinations
    header_sets = [
        {
            "name": "Only Client ID",
            "headers": {
                "Amazon-Advertising-API-ClientId": settings.amazon_ads_client_id,
            }
        },
        {
            "name": "Client ID + Content-Type",
            "headers": {
                "Amazon-Advertising-API-ClientId": settings.amazon_ads_client_id,
                "Content-Type": "application/json",
            }
        },
        {
            "name": "Client ID + User-Agent",
            "headers": {
                "Amazon-Advertising-API-ClientId": settings.amazon_ads_client_id,
                "Content-Type": "application/json",
                "User-Agent": "AmazonAdvertisingAPI/1.0",
            }
        },
        {
            "name": "With X-Amz-Client-Id",
            "headers": {
                "Amazon-Advertising-API-ClientId": settings.amazon_ads_client_id,
                "X-Amz-Client-Id": settings.amazon_ads_client_id,
                "Content-Type": "application/json",
            }
        }
    ]
    
    for base_url in base_urls:
        print(f"\n\nTesting base URL: {base_url}")
        print("-" * 50)
        
        async with httpx.AsyncClient(base_url=base_url, timeout=10.0) as client:
            for header_set in header_sets:
                print(f"\n{header_set['name']}:")
                
                try:
                    response = await client.get(
                        "/testAccounts",
                        headers=header_set['headers']
                    )
                    print(f"  GET /testAccounts: {response.status_code}")
                    
                    if response.status_code != 401:
                        print(f"  Response: {response.text[:100]}...")
                        
                    # If we get something other than 401, this might be the right config
                    if response.status_code in [200, 400, 422]:
                        print("  ✅ This configuration might work!")
                        
                except httpx.ConnectError:
                    print(f"  ❌ Connection failed")
                except Exception as e:
                    print(f"  Error: {type(e).__name__}: {e}")
    
    print("\n\n🤔 Analysis:")
    print("The consistent 401 errors suggest:")
    print("1. The Client ID might not be authorized for the Test Account API")
    print("2. The Test Account API might require separate registration")
    print("3. There might be IP allowlisting or other restrictions")
    print("\nThe OpenAPI spec shows this is the correct endpoint and header.")
    print("The issue is likely with API access permissions, not the code.")


if __name__ == "__main__":
    asyncio.run(test_variations())