#!/usr/bin/env python3
"""Make a direct call to Amazon Ads API using Openbridge tokens."""

import asyncio
import httpx
import json


async def direct_test():
    """Test direct API call."""
    print("🎯 Direct Amazon Ads API Test")
    print("=" * 50)
    
    # Step 1: Get JWT from Openbridge
    refresh_token = "***REDACTED_OPENBRIDGE_TOKEN***"
    
    async with httpx.AsyncClient(timeout=60.0) as client:
        print("\n1. Getting JWT from Openbridge...")
        jwt_response = await client.post(
            "https://authentication.api.openbridge.io/auth/api/ref",
            json={
                "data": {
                    "type": "APIAuth",
                    "attributes": {"refresh_token": refresh_token}
                }
            }
        )
        
        jwt_token = jwt_response.json()["data"]["attributes"]["token"]
        print(f"   ✅ Got JWT")
        
        # Step 2: Get Amazon Ads token for identity 6163 (A3OMVOFWPNPB8E)
        print("\n2. Getting Amazon Ads token...")
        token_response = await client.get(
            "https://service.api.openbridge.io/service/amzadv/token/3175",
            headers={
                "Authorization": f"Bearer {jwt_token}",
                "Accept": "application/vnd.api+json",
            }
        )
        
        if token_response.status_code != 200:
            print(f"   ❌ Failed to get token: {token_response.status_code}")
            print(f"   Response: {token_response.text}")
            return
        
        token_data = token_response.json()["data"]
        access_token = token_data["access_token"]
        client_id = token_data["client_id"]
        
        print(f"   ✅ Got Amazon Ads token")
        print(f"   Client ID: {client_id}")
        
        # Step 3: Try different endpoints
        print("\n3. Testing different Amazon Ads API endpoints...")
        
        # Try different header combinations
        base_headers = {
            "Authorization": f"Bearer {access_token}",
            "Amazon-Advertising-API-ClientId": client_id,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        
        endpoints = [
            ("Test Accounts", "https://advertising-api.amazon.com/testAccounts", {}),
            ("Profiles with Scope", "https://advertising-api.amazon.com/v2/profiles", 
             {"Amazon-Advertising-API-Scope": "2984328618318898"}),
            ("Profiles Basic", "https://advertising-api.amazon.com/v2/profiles", {}),
            ("Manager Accounts", "https://advertising-api.amazon.com/v2/managerAccounts", {}),
        ]
        
        for name, url, extra_headers in endpoints:
            print(f"\n   Testing {name}: {url}")
            
            headers = base_headers.copy()
            headers.update(extra_headers)
            
            response = await client.get(url, headers=headers)
            print(f"   Status: {response.status_code}")
            
            if response.status_code == 200:
                print(f"   ✅ SUCCESS!")
                data = response.json()
                print(f"   Response: {json.dumps(data, indent=2)[:500]}...")
                break
            elif response.status_code == 400:
                print(f"   Bad Request: {response.text[:100]}...")
            elif response.status_code == 401:
                print(f"   Unauthorized: {response.text[:100]}...")
            elif response.status_code == 403:
                print(f"   Forbidden: {response.text[:100]}...")
            else:
                print(f"   Other: {response.text[:100]}...")


if __name__ == "__main__":
    asyncio.run(direct_test())