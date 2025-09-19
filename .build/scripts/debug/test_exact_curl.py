#!/usr/bin/env python3
"""Test exactly as shown in Amazon Ads API documentation."""

import asyncio
import httpx
import urllib.parse
from dotenv import load_dotenv
from amazon_ads_mcp.config.settings import settings

load_dotenv()


async def test_exact_curl():
    """Test token refresh exactly as shown in docs."""
    print("🔍 Testing Exact cURL Implementation")
    print("=" * 50)
    
    # Prepare data exactly as in the cURL example
    token_data = {
        "grant_type": "refresh_token",
        "client_id": settings.amazon_ads_client_id,
        "refresh_token": settings.amazon_ads_refresh_token,
        "client_secret": settings.amazon_ads_client_secret,
    }
    
    print("\n1. Token Request (matching cURL):")
    print(f"   URL: https://api.amazon.com/auth/o2/token")
    print(f"   Data: grant_type=refresh_token&client_id=***&refresh_token=***&client_secret=***")
    
    async with httpx.AsyncClient() as client:
        # Method 1: Exactly like cURL with form data
        response = await client.post(
            "https://api.amazon.com/auth/o2/token",
            data=token_data,  # httpx automatically encodes as form data
        )
        
        print(f"\n   Response Status: {response.status_code}")
        if response.status_code == 200:
            token_response = response.json()
            print("   ✅ Token Response:")
            print(f"   - access_token: {token_response['access_token'][:30]}...")
            print(f"   - token_type: {token_response['token_type']}")
            print(f"   - expires_in: {token_response['expires_in']}")
            print(f"   - refresh_token: {'present' if 'refresh_token' in token_response else 'not returned'}")
            
            access_token = token_response['access_token']
            
            # Now test the API call with exact header format from docs
            print("\n2. API Request with Token:")
            print(f'   Authorization: "Bearer {access_token[:30]}..."')
            
            # Make API request exactly as documented
            api_response = await client.get(
                f"{settings.region_endpoint}/v2/profiles",
                headers={
                    "Authorization": f"Bearer {access_token}",  # Exact format from docs
                    "Amazon-Advertising-API-ClientId": settings.amazon_ads_client_id,
                }
            )
            
            print(f"\n   API Response Status: {api_response.status_code}")
            if api_response.status_code != 200:
                print(f"   Response: {api_response.text}")
            else:
                print("   ✅ Success!")
                
        else:
            print(f"   ❌ Token request failed: {response.text}")
    
    # Also test with curl command directly
    print("\n\n3. Actual cURL command to test:")
    print("curl \\")
    print("    -X POST \\")
    print(f'    --data "grant_type=refresh_token&client_id={settings.amazon_ads_client_id}&refresh_token={settings.amazon_ads_refresh_token[:20]}...&client_secret={settings.amazon_ads_client_secret[:20]}..." \\')
    print("    https://api.amazon.com/auth/o2/token")
    
    print("\n\nThen test API with:")
    print("curl \\")
    print(f'    -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \\')
    print(f'    -H "Amazon-Advertising-API-ClientId: {settings.amazon_ads_client_id}" \\')
    print(f"    {settings.region_endpoint}/v2/profiles")


if __name__ == "__main__":
    asyncio.run(test_exact_curl())