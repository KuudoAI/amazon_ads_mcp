#!/usr/bin/env python3
"""Test the My Store identity (type 16)."""

import asyncio
import httpx
from amazon_ads_mcp.auth.openbridge_auth import OpenbridgeAuth


async def test_my_store():
    """Test My Store identity."""
    print("🏪 Testing My Store Identity")
    print("=" * 50)
    
    openbridge = OpenbridgeAuth("***REDACTED_OPENBRIDGE_TOKEN***")
    
    # Test both My Store identities
    my_store_ids = ["6331", "12845"]
    
    for store_id in my_store_ids:
        print(f"\nTesting identity ID: {store_id}")
        
        try:
            # Get token
            token_info = await openbridge.get_amazon_ads_token(store_id)
            print(f"✅ Got token!")
            print(f"   Client ID: {token_info['client_id']}")
            
            # Test API
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    "https://advertising-api.amazon.com/v2/profiles",
                    headers={
                        "Authorization": f"Bearer {token_info['access_token']}",
                        "Amazon-Advertising-API-ClientId": token_info['client_id'],
                        "Content-Type": "application/json",
                        "Amazon-Advertising-API-Scope": "2984328618318898",
                    }
                )
                
                print(f"   API Response: {response.status_code}")
                
                if response.status_code == 200:
                    profiles = response.json()
                    print(f"   ✅ SUCCESS! Found {len(profiles)} profiles")
                    print(f"\n🎉 Working identity found: ID {store_id}")
                    await openbridge.close()
                    return
                else:
                    print(f"   Response: {response.text[:100]}...")
                    
        except Exception as e:
            print(f"   Error: {e}")
    
    await openbridge.close()


if __name__ == "__main__":
    asyncio.run(test_my_store())