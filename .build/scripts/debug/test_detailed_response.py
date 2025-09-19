#!/usr/bin/env python3
"""Test API with detailed response inspection."""

import asyncio
import httpx
import json
from dotenv import load_dotenv
from amazon_ads_mcp.config.settings import settings
from amazon_ads_mcp.utils.auth import AmazonAdsAuth

load_dotenv()


async def test_detailed():
    """Test API with detailed header and response inspection."""
    print("🔍 Detailed API Response Analysis")
    print("=" * 50)
    
    # Initialize authentication
    auth = AmazonAdsAuth(
        client_id=settings.amazon_ads_client_id,
        client_secret=settings.amazon_ads_client_secret,
        refresh_token=settings.amazon_ads_refresh_token,
    )
    
    await auth.get_access_token()
    print("✅ Got access token")
    
    # Create client with detailed logging
    client = httpx.AsyncClient(
        base_url=settings.region_endpoint,
        timeout=30.0,
    )
    
    # Test with different header combinations
    print("\n1. Testing with basic headers:")
    headers = {
        "Authorization": f"Bearer {auth.access_token}",
        "Amazon-Advertising-API-ClientId": settings.amazon_ads_client_id,
        "Content-Type": "application/json",
    }
    
    print("   Request headers:")
    for k, v in headers.items():
        if k == "Authorization":
            print(f"   - {k}: Bearer {v[7:20]}...")
        else:
            print(f"   - {k}: {v}")
    
    try:
        response = await client.get("/v2/profiles", headers=headers)
        print(f"\n   Response status: {response.status_code}")
        print("   Response headers:")
        for k, v in response.headers.items():
            print(f"   - {k}: {v}")
        print(f"\n   Response body: {response.text}")
    except Exception as e:
        print(f"   Error: {e}")
    
    # Test with additional headers that might be required
    print("\n2. Testing with additional headers:")
    additional_headers = {
        **headers,
        "Accept": "application/json",
        "User-Agent": "amazon-ads-mcp/1.0",
        "Amazon-Advertising-API-Scope": "profile",  # Try adding scope
    }
    
    try:
        response = await client.get("/v2/profiles", headers=additional_headers)
        print(f"   Response status: {response.status_code}")
        if response.status_code != 200:
            print(f"   Response: {response.text}")
    except Exception as e:
        print(f"   Error: {e}")
    
    # Test the test account endpoint with all variations
    print("\n3. Testing test account endpoint:")
    
    # According to the OpenAPI spec, this endpoint might need different auth
    test_endpoints = [
        "/testAccounts",
        "/v2/testAccounts",
        "/test/accounts",
    ]
    
    for endpoint in test_endpoints:
        print(f"\n   Trying {endpoint}:")
        try:
            response = await client.get(endpoint, headers=headers)
            print(f"   - Status: {response.status_code}")
            if response.status_code != 404:  # If not "not found"
                print(f"   - Response: {response.text[:200]}...")
                
                # If we get a 401, check if there's more info
                if response.status_code == 401:
                    try:
                        error_data = response.json()
                        print(f"   - Parsed error: {json.dumps(error_data, indent=2)}")
                    except:
                        pass
        except Exception as e:
            print(f"   - Error: {e}")
    
    # Check if we need to use a different authentication method
    print("\n4. Checking authentication requirements:")
    print("   The API might require:")
    print("   - Account to be approved for API access")
    print("   - Specific OAuth scopes during authorization")
    print("   - An advertising profile to be created first")
    print("   - Different authentication for test endpoints")
    
    await client.aclose()
    print("\n✅ Analysis complete!")


if __name__ == "__main__":
    asyncio.run(test_detailed())