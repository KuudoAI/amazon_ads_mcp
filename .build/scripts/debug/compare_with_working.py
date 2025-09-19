#!/usr/bin/env python3
"""Compare our implementation with working code."""

import asyncio
import httpx
import json
import base64
from dotenv import load_dotenv
from amazon_ads_mcp.config.settings import settings
from amazon_ads_mcp.utils.auth import AmazonAdsAuth

load_dotenv()


async def test_token_details():
    """Test and inspect token details."""
    print("🔍 Token and Request Analysis")
    print("=" * 50)
    
    # Get token the way we do it
    auth = AmazonAdsAuth(
        client_id=settings.amazon_ads_client_id,
        client_secret=settings.amazon_ads_client_secret,
        refresh_token=settings.amazon_ads_refresh_token,
    )
    
    print("\n1. Token Generation:")
    await auth.get_access_token()
    print(f"   ✅ Got access token")
    print(f"   Token starts with: {auth.access_token[:20]}...")
    print(f"   Token length: {len(auth.access_token)}")
    
    # Check if it's a JWT or opaque token
    if auth.access_token.startswith("Atza|"):
        print("   Token type: Amazon LWA opaque token (correct)")
    else:
        print("   Token type: Unknown format")
    
    # Test the exact request that should work
    print("\n2. Testing Exact API Request:")
    
    client = httpx.AsyncClient(timeout=30.0)
    
    # Exact headers as per Amazon Ads API docs
    headers = {
        "Authorization": f"Bearer {auth.access_token}",
        "Amazon-Advertising-API-ClientId": settings.amazon_ads_client_id,
        "Content-Type": "application/json",
    }
    
    print("   Request details:")
    print(f"   URL: {settings.region_endpoint}/v2/profiles")
    print("   Headers:")
    for k, v in headers.items():
        if k == "Authorization":
            print(f"     {k}: Bearer {v[7:30]}...")
        else:
            print(f"     {k}: {v}")
    
    # Make the request
    response = await client.get(
        f"{settings.region_endpoint}/v2/profiles",
        headers=headers
    )
    
    print(f"\n   Response Status: {response.status_code}")
    print(f"   Response Headers:")
    for k, v in response.headers.items():
        if k.lower() in ['x-amz-request-id', 'x-amzn-requestid', 'x-amzn-errortype', 'date']:
            print(f"     {k}: {v}")
    
    if response.status_code != 200:
        print(f"\n   Response Body: {response.text}")
    
    # Try with raw httpx to rule out any wrapper issues
    print("\n3. Raw HTTPX Request (no wrappers):")
    
    raw_response = await client.request(
        method="GET",
        url=f"{settings.region_endpoint}/v2/profiles",
        headers={
            "Authorization": f"Bearer {auth.access_token}",
            "Amazon-Advertising-API-ClientId": settings.amazon_ads_client_id,
            "Content-Type": "application/json",
        }
    )
    
    print(f"   Status: {raw_response.status_code}")
    
    await client.aclose()
    
    print("\n\n📋 Things to check in your working codebase:")
    print("1. Is the Client ID exactly the same?")
    print("2. Is the refresh token from the same account/region?")
    print("3. Are there any proxy or network differences?")
    print("4. Is the working code using any additional headers?")
    print("5. Is the endpoint URL exactly the same?")


if __name__ == "__main__":
    asyncio.run(test_token_details())