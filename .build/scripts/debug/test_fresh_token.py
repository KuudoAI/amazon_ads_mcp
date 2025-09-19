#!/usr/bin/env python3
"""Get fresh token and test immediately."""

import asyncio
import httpx
import json


async def test_fresh():
    """Get a fresh token and test it immediately."""
    print("🔄 Getting Fresh Token and Testing")
    print("=" * 50)
    
    refresh_token = "***REDACTED_OPENBRIDGE_TOKEN***"
    
    async with httpx.AsyncClient(timeout=60.0) as client:
        # Step 1: Get JWT
        print("\n1. Getting JWT...")
        auth_response = await client.post(
            "https://authentication.api.openbridge.io/auth/api/ref",
            json={
                "data": {
                    "type": "APIAuth",
                    "attributes": {"refresh_token": refresh_token}
                }
            }
        )
        
        jwt_token = auth_response.json()["data"]["attributes"]["token"]
        print(f"   JWT: {jwt_token[:50]}...")
        
        # Step 2: Get identities
        print("\n2. Getting identities...")
        ri_response = await client.get(
            "https://remote-identity.api.openbridge.io/ri",
            headers={
                "Authorization": f"Bearer {jwt_token}",
                "Accept": "application/vnd.api+json",
            }
        )
        
        identities = ri_response.json()["data"]
        
        # Get tokens for ALL Amazon Ads identities and test them
        for identity in identities:
            if identity.get('relationships', {}).get('remote_identity_type', {}).get('data', {}).get('id') == '17':
                remote_id = identity['id']
                name = identity['attributes']['name']
                print(f"\n3. Testing identity: {name} (ID: {remote_id})")
                
                # Get token
                token_response = await client.get(
                    f"https://service.api.openbridge.io/service/amzadv/token/{remote_id}",
                    headers={
                        "Authorization": f"Bearer {jwt_token}",
                        "Accept": "application/vnd.api+json",
                    }
                )
                
                if token_response.status_code == 200:
                    token_data = token_response.json()["data"]
                    access_token = token_data["access_token"]
                    client_id = token_data["client_id"]
                    
                    print(f"   Got token for client: {client_id}")
                    
                    # Test immediately
                    headers = {
                        "Authorization": f"Bearer {access_token}",
                        "Amazon-Advertising-API-ClientId": client_id,
                        "Content-Type": "application/json",
                    }
                    
                    # Test all regions
                    for region, base_url in [
                        ("NA", "https://advertising-api.amazon.com"),
                        ("EU", "https://advertising-api-eu.amazon.com"),
                        ("FE", "https://advertising-api-fe.amazon.com"),
                    ]:
                        response = await client.get(
                            f"{base_url}/v2/profiles",
                            headers=headers
                        )
                        
                        print(f"   {region}: Status {response.status_code}", end="")
                        
                        if response.status_code == 200:
                            profiles = response.json()
                            print(f" ✅ SUCCESS! Found {len(profiles)} profiles")
                            
                            # Show first profile
                            if profiles:
                                p = profiles[0]
                                print(f"\n   First profile:")
                                print(f"   - ID: {p.get('profileId')}")
                                print(f"   - Country: {p.get('countryCode')}")
                                print(f"   - Type: {p.get('accountInfo', {}).get('type')}")
                            
                            # Found working region, save config
                            print(f"\n✅ Working configuration found!")
                            print(f"   Identity: {name}")
                            print(f"   Client ID: {client_id}")
                            print(f"   Region: {region} ({base_url})")
                            return
                        else:
                            print(f" - {response.text[:50]}...")


if __name__ == "__main__":
    asyncio.run(test_fresh())