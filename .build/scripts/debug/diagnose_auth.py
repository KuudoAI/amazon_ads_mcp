#!/usr/bin/env python3
"""Diagnose authentication issues with Amazon Ads API."""

import asyncio
import httpx
import base64
import json
from dotenv import load_dotenv
from amazon_ads_mcp.config.settings import settings
from amazon_ads_mcp.utils.auth import AmazonAdsAuth

load_dotenv()


async def diagnose_auth():
    """Diagnose authentication and API access."""
    print("🔍 Amazon Ads API Authentication Diagnostics")
    print("=" * 50)
    
    # Check credentials
    print("\n1. Checking Credentials:")
    print(f"   Client ID: {settings.amazon_ads_client_id[:20]}...")
    print(f"   Has Client Secret: {'Yes' if settings.amazon_ads_client_secret else 'No'}")
    print(f"   Has Refresh Token: {'Yes' if settings.amazon_ads_refresh_token else 'No'}")
    print(f"   Region: {settings.amazon_ads_region}")
    print(f"   Endpoint: {settings.region_endpoint}")
    
    # Initialize auth
    auth = AmazonAdsAuth(
        client_id=settings.amazon_ads_client_id,
        client_secret=settings.amazon_ads_client_secret,
        refresh_token=settings.amazon_ads_refresh_token,
    )
    
    # Get access token
    print("\n2. Testing Token Refresh:")
    try:
        await auth.get_access_token()
        print("   ✅ Successfully got access token")
        print(f"   Token expires at: {auth.token_expires_at}")
        
        # Decode token to see claims (if it's a JWT)
        try:
            # Try to decode as JWT (might not work if it's opaque)
            parts = auth.access_token.split('.')
            if len(parts) == 3:
                # It's a JWT
                payload = base64.urlsafe_b64decode(parts[1] + '==')
                claims = json.loads(payload)
                print("   Token claims:", json.dumps(claims, indent=2))
        except:
            print("   Token is opaque (not JWT)")
            
    except Exception as e:
        print(f"   ❌ Failed to get access token: {e}")
        return
    
    # Test different endpoints
    print("\n3. Testing API Endpoints:")
    
    client = httpx.AsyncClient(timeout=30.0)
    
    endpoints_to_test = [
        ("Production API", settings.region_endpoint),
        ("Test/Sandbox API", settings.region_endpoint.replace("advertising-api", "advertising-api-test")),
    ]
    
    for name, base_url in endpoints_to_test:
        print(f"\n   Testing {name}: {base_url}")
        
        # Update client base URL
        headers = auth.get_auth_headers()
        
        # Test root endpoint
        try:
            response = await client.get(
                f"{base_url}/",
                headers=headers
            )
            print(f"   - Root endpoint: {response.status_code}")
        except Exception as e:
            print(f"   - Root endpoint: Error - {e}")
        
        # Test profiles
        try:
            response = await client.get(
                f"{base_url}/v2/profiles",
                headers=headers
            )
            print(f"   - Profiles endpoint: {response.status_code}")
            if response.status_code != 200:
                print(f"     Response: {response.text[:200]}...")
        except Exception as e:
            print(f"   - Profiles endpoint: Error - {e}")
        
        # Test accounts
        try:
            response = await client.get(
                f"{base_url}/testAccounts",
                headers=headers
            )
            print(f"   - Test accounts endpoint: {response.status_code}")
            if response.status_code != 200:
                print(f"     Response: {response.text[:200]}...")
        except Exception as e:
            print(f"   - Test accounts endpoint: Error - {e}")
    
    await client.aclose()
    
    print("\n4. Common Issues:")
    print("   - 401: Check if account is registered for API access")
    print("   - 403: Check if account has proper permissions")
    print("   - 503: Service temporarily unavailable")
    print("\n   To register for API access:")
    print("   1. Go to https://advertising.amazon.com/API/")
    print("   2. Register your application")
    print("   3. Wait for approval")
    print("   4. Ensure you have an active advertising account")


if __name__ == "__main__":
    asyncio.run(diagnose_auth())