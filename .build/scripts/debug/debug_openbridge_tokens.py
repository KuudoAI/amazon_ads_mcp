#!/usr/bin/env python3
"""Debug Openbridge token exchange to see exact response format."""

import asyncio
import httpx
import json
from dotenv import load_dotenv
import jwt as pyjwt

load_dotenv()


async def debug_openbridge():
    """Debug the exact response from Openbridge token endpoints."""
    print("🔍 Debugging Openbridge Token Exchange")
    print("=" * 50)
    
    refresh_token = "***REDACTED_OPENBRIDGE_TOKEN***"
    
    async with httpx.AsyncClient() as client:
        # Step 1: Get JWT
        print("\n1. Getting JWT from Openbridge...")
        auth_response = await client.post(
            "https://authentication.api.openbridge.io/auth/api/ref",
            json={
                "data": {
                    "type": "APIAuth",
                    "attributes": {"refresh_token": refresh_token}
                }
            },
            headers={"Content-Type": "application/json"},
            timeout=30.0
        )
        
        print(f"   Status: {auth_response.status_code}")
        auth_data = auth_response.json()
        jwt_token = auth_data.get("data", {}).get("attributes", {}).get("token")
        print(f"   JWT: {jwt_token[:50]}...")
        
        # Step 2: Get remote identities
        print("\n2. Getting remote identities...")
        ri_response = await client.get(
            "https://remote-identity.api.openbridge.io/ri",
            headers={
                "Authorization": f"Bearer {jwt_token}",
                "Accept": "application/vnd.api+json",
            }
        )
        
        identities = ri_response.json()["data"]
        
        # Find Amazon Ads identities
        for identity in identities:
            if identity.get('relationships', {}).get('remote_identity_type', {}).get('data', {}).get('id') == '17':
                remote_id = identity['id']
                name = identity['attributes']['name']
                print(f"\n3. Getting token for Amazon Ads identity: {name} (ID: {remote_id})")
                
                # Get token with full debugging
                token_response = await client.get(
                    f"https://service.api.openbridge.io/service/amzadv/token/{remote_id}",
                    headers={
                        "Authorization": f"Bearer {jwt_token}",
                        "Accept": "application/vnd.api+json",
                    },
                    timeout=60.0
                )
                
                print(f"   Status: {token_response.status_code}")
                print(f"   Headers: {dict(token_response.headers)}")
                
                if token_response.status_code == 200:
                    # Print raw response
                    raw_text = token_response.text
                    print(f"\n   Raw response: {raw_text[:500]}...")
                    
                    # Parse JSON
                    token_data = token_response.json()
                    print(f"\n   Parsed JSON structure:")
                    print(json.dumps(token_data, indent=2))
                    
                    # Extract token and client ID
                    if 'data' in token_data:
                        access_token = token_data['data'].get('access_token')
                        client_id = token_data['data'].get('client_id')
                    else:
                        access_token = token_data.get('access_token')
                        client_id = token_data.get('client_id')
                    
                    print(f"\n   Access Token: {access_token[:50] if access_token else 'NOT FOUND'}...")
                    print(f"   Client ID: {client_id if client_id else 'NOT FOUND'}")
                    
                    # If we found the token, test it
                    if access_token and client_id:
                        print("\n4. Testing token against Amazon Ads API...")
                        
                        headers = {
                            "Authorization": f"Bearer {access_token}",
                            "Amazon-Advertising-API-ClientId": client_id,
                            "Content-Type": "application/json",
                            "Accept": "application/json",
                        }
                        
                        # Test test accounts endpoint
                        test_response = await client.get(
                            "https://advertising-api.amazon.com/testAccounts",
                            headers=headers
                        )
                        
                        print(f"   Test Accounts endpoint status: {test_response.status_code}")
                        print(f"   Response: {test_response.text[:200]}...")
                        
                        # Test profiles endpoint 
                        profiles_response = await client.get(
                            "https://advertising-api.amazon.com/v2/profiles",
                            headers=headers
                        )
                        
                        print(f"\n   Profiles endpoint status: {profiles_response.status_code}")
                        print(f"   Response: {profiles_response.text[:200]}...")
                
                # Only test first Amazon Ads identity
                break


if __name__ == "__main__":
    asyncio.run(debug_openbridge())