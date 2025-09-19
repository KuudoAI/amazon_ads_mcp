#!/usr/bin/env python3
"""Test Amazon Ads API with Openbridge tokens."""

import asyncio
import httpx
from amazon_ads_mcp.config.settings import settings


async def test_amazon_ads():
    """Test Amazon Ads API with the tokens we got from Openbridge."""
    print("🎯 Testing Amazon Ads API with Openbridge Tokens")
    print("=" * 50)
    
    # Token from second identity (AVVXJ277848G0)
    access_token = "Atza|IwEBIKNVmwB5msEaoqkcH5tWGaj9abPrTrvEw0E1pyB9fmlCwfTHz9Z83Q4JPmrGqYkQbcL5tM9smsWVHMBGfKEO5XH5TwGsQahaGuKQEGUODiX018-MGi-4-hmkWZ9q9J61-6VKNVP2s1QiLsHFUPQE6mi1WG6UB5EtYO9q1aekp6LO0Q_nftgC30ltGog4-S57PGB3tqKSGUpaG807j1fRETCWrYzRI1K-keftzvYnV-O9VVz3is7ktnLS_Fqfe0HlUdjGcxsL-2yAGh_kkN1HJNNvpORVUgDC5x1hqkmNkpcU4pgQ0sbCj9G5xEi5xkcfUQjjl4SbSXknQfMrWs6VA6V3"
    client_id = "amzn1.application-oa2-client.5571543b64ac404fafb8ff468c898443"
    
    print(f"Using Client ID: {client_id}")
    print(f"Access Token: {access_token[:50]}...")
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Amazon-Advertising-API-ClientId": client_id,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        # Test different regional endpoints
        endpoints = [
            ("NA", "https://advertising-api.amazon.com"),
            ("EU", "https://advertising-api-eu.amazon.com"),
            ("FE", "https://advertising-api-fe.amazon.com"),
        ]
        
        for region, base_url in endpoints:
            print(f"\n📍 Testing {region} region ({base_url})...")
            
            try:
                response = await client.get(
                    f"{base_url}/v2/profiles",
                    headers=headers
                )
                
                print(f"   Status: {response.status_code}")
                
                if response.status_code == 200:
                    print("   ✅ SUCCESS! Amazon Ads API is working!")
                    profiles = response.json()
                    print(f"   Found {len(profiles)} profiles:")
                    
                    for profile in profiles[:3]:  # Show first 3
                        print(f"\n   Profile:")
                        print(f"   - ID: {profile.get('profileId')}")
                        print(f"   - Country: {profile.get('countryCode')}")
                        print(f"   - Currency: {profile.get('currencyCode')}")
                        print(f"   - Account Type: {profile.get('accountInfo', {}).get('type')}")
                        print(f"   - Marketplace: {profile.get('accountInfo', {}).get('marketplaceStringId')}")
                    
                    # We found profiles, so this is the correct region
                    break
                    
                elif response.status_code == 401:
                    print("   ❌ Unauthorized - token might be for different region")
                    print(f"   Response: {response.text[:200]}...")
                else:
                    print(f"   Response: {response.text[:200]}...")
                    
            except Exception as e:
                print(f"   Error: {e}")


if __name__ == "__main__":
    asyncio.run(test_amazon_ads())