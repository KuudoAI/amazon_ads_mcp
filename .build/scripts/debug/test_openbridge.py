#!/usr/bin/env python3
"""Test Openbridge authentication for Amazon Ads API."""

import asyncio
import os
from dotenv import load_dotenv

load_dotenv()


async def test_openbridge():
    """Test Openbridge authentication."""
    print("🌉 Testing Openbridge Authentication")
    print("=" * 50)
    
    # Set up your Openbridge bearer token
    bearer_token = "***REDACTED_OPENBRIDGE_TOKEN***"
    
    print(f"\n1. Using Bearer Token: {bearer_token[:20]}...")
    
    print("\n2. Listing Remote Identities...")
    try:
        import httpx
        async with httpx.AsyncClient() as client:
            # Use the bearer token directly
            response = await client.get(
                "https://remote-identity.api.openbridge.io/ri",
                headers={
                    "Authorization": f"Bearer {bearer_token}",
                    "Accept": "application/json",
                }
            )
            print(f"   Response status: {response.status_code}")
            if response.status_code != 200:
                print(f"   Response: {response.text}")
                return
            
            identities = response.json()
        print(f"   Found {len(identities)} remote identities:")
        
        for identity in identities:
            print(f"\n   Identity: {identity.get('name', 'Unknown')}")
            print(f"   - ID: {identity.get('id')}")
            print(f"   - Service: {identity.get('service_type')}")
            print(f"   - Status: {identity.get('status')}")
            
            # If it's an Amazon Ads identity, try to get a token
            if identity.get("service_type") == "amzadv" or "amazon" in str(identity.get("name", "")).lower():
                remote_identity_id = identity['id']
                print(f"\n3. Getting Amazon Ads token for identity {remote_identity_id}...")
                
                # Call the token endpoint
                token_response = await client.get(
                    f"https://service.api.openbridge.io/service/amzadv/token/{remote_identity_id}",
                    headers={
                        "Authorization": f"Bearer {bearer_token}",
                        "Accept": "application/json",
                    }
                )
                
                print(f"   Token response status: {token_response.status_code}")
                if token_response.status_code == 200:
                    token_data = token_response.json()
                    print("   ✅ Got token data:")
                    for key, value in token_data.items():
                        if key in ["access_token", "token"]:
                            print(f"   - {key}: {str(value)[:30]}...")
                        else:
                            print(f"   - {key}: {value}")
                    
                    # Test Amazon Ads API with this token
                    if "access_token" in token_data or "token" in token_data:
                        amazon_token = token_data.get("access_token") or token_data.get("token")
                        print(f"\n4. Testing Amazon Ads API with Openbridge token...")
                        
                        from amazon_ads_mcp.config.settings import settings
                        
                        headers = {
                            "Authorization": f"Bearer {amazon_token}",
                            "Content-Type": "application/json",
                        }
                        
                        # Add client ID if provided
                        if "client_id" in token_data:
                            headers["Amazon-Advertising-API-ClientId"] = token_data["client_id"]
                        
                        api_response = await client.get(
                            f"{settings.region_endpoint}/v2/profiles",
                            headers=headers,
                        )
                        print(f"   API Response: {api_response.status_code}")
                        if api_response.status_code == 200:
                            print("   ✅ Success! Openbridge authentication works!")
                            profiles = api_response.json()
                            print(f"   Found {len(profiles)} profiles")
                        else:
                            print(f"   Response: {api_response.text}")
                else:
                    print(f"   Error: {token_response.text}")
                    
    except Exception as e:
        print(f"   Error: {e}")
        print("\n   Make sure your Openbridge API credentials are correct")


if __name__ == "__main__":
    asyncio.run(test_openbridge())