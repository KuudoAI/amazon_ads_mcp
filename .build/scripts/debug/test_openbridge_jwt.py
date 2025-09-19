#!/usr/bin/env python3
"""Test Openbridge authentication using JWT exchange."""

import asyncio
import httpx
import json
from dotenv import load_dotenv

load_dotenv()


async def test_openbridge_jwt():
    """Test Openbridge JWT authentication flow."""
    print("🌉 Testing Openbridge JWT Authentication")
    print("=" * 50)
    
    # Your Openbridge refresh token
    refresh_token = "***REDACTED_OPENBRIDGE_TOKEN***"
    
    print(f"\n1. Using Refresh Token: {refresh_token[:20]}...")
    
    # Step 1: Exchange refresh token for JWT
    print("\n2. Exchanging refresh token for JWT...")
    
    auth_endpoint = "https://authentication.api.openbridge.io/auth/api/ref"
    
    payload = {
        "data": {
            "type": "APIAuth",
            "attributes": {
                "refresh_token": refresh_token
            }
        }
    }
    
    async with httpx.AsyncClient() as client:
        try:
            # Get JWT from auth server
            response = await client.post(
                auth_endpoint,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=30.0
            )
            
            print(f"   Auth server response: {response.status_code}")
            
            if response.status_code not in [200, 202]:
                print(f"   Error: {response.text}")
                return
                
            auth_data = response.json()
            jwt_token = auth_data.get("data", {}).get("attributes", {}).get("token")
            
            if not jwt_token:
                print("   ❌ No JWT token in response")
                print(f"   Response: {json.dumps(auth_data, indent=2)}")
                return
                
            print(f"   ✅ Got JWT token: {jwt_token[:50]}...")
            
            # Decode JWT to see claims (without verification)
            import jwt as pyjwt
            try:
                claims = pyjwt.decode(jwt_token, options={"verify_signature": False})
                print("\n   JWT Claims:")
                for key, value in claims.items():
                    print(f"     {key}: {value}")
            except Exception as e:
                print(f"   Could not decode JWT: {e}")
            
            # Step 2: Use JWT to list remote identities
            print("\n3. Using JWT to access Openbridge API...")
            
            ri_response = await client.get(
                "https://remote-identity.api.openbridge.io/ri",
                headers={
                    "Authorization": f"Bearer {jwt_token}",
                    "Accept": "application/vnd.api+json",  # JSON:API format
                }
            )
            
            print(f"   Remote identities response: {ri_response.status_code}")
            
            if ri_response.status_code == 200:
                response_data = ri_response.json()
                
                # Handle JSON:API format
                if isinstance(response_data, dict) and "data" in response_data:
                    identities = response_data["data"]
                else:
                    identities = response_data
                    
                print(f"   ✅ Found {len(identities)} remote identities:")
                
                # Debug: print first identity structure
                if identities:
                    print(f"\n   Debug - First identity structure: {json.dumps(identities[0], indent=2)}")
                
                for identity in identities:
                    # Handle both dict and JSON:API format
                    if isinstance(identity, dict):
                        id_val = identity.get('id')
                        attrs = identity.get('attributes', {})
                        name = attrs.get('name', identity.get('name', 'Unknown'))
                        service = attrs.get('service_type', identity.get('service_type'))
                        status = attrs.get('status', identity.get('status'))
                    else:
                        continue
                        
                    # Get type info
                    relationships = identity.get('relationships', {})
                    type_id = relationships.get('remote_identity_type', {}).get('data', {}).get('id')
                    
                    print(f"\n   Identity: {name}")
                    print(f"   - ID: {id_val}")
                    print(f"   - Type ID: {type_id}")
                    print(f"   - Service: {service}")
                    print(f"   - Status: {status}")
                    
                    # Check if this is an Amazon Ads identity
                    # Look for specific indicators
                    is_amzadv = False
                    remote_type_id = None
                    
                    # Check relationships for type
                    relationships = identity.get('relationships', {})
                    if relationships.get('remote_identity_type', {}).get('data', {}).get('id') == '17':
                        is_amzadv = True
                        remote_type_id = 17
                        
                    if is_amzadv:
                        remote_id = id_val
                        print(f"\n4. Getting Amazon Ads token for identity {remote_id}...")
                        
                        try:
                            token_response = await client.get(
                                f"https://service.api.openbridge.io/service/amzadv/token/{remote_id}",
                                headers={
                                    "Authorization": f"Bearer {jwt_token}",
                                    "Accept": "application/vnd.api+json",
                                },
                                timeout=60.0  # Longer timeout for token endpoint
                            )
                        except httpx.ReadTimeout:
                            print(f"   ⏱️  Timeout getting token for identity {remote_id}")
                            continue
                        
                        print(f"   Token response: {token_response.status_code}")
                        
                        if token_response.status_code == 200:
                            token_data = token_response.json()
                            print("   ✅ Got Amazon Ads token data:")
                            for key, value in token_data.items():
                                if key in ["access_token", "token"]:
                                    print(f"   - {key}: {str(value)[:30]}...")
                                else:
                                    print(f"   - {key}: {value}")
                            
                            # Test Amazon Ads API
                            if "access_token" in token_data or "token" in token_data:
                                amazon_token = token_data.get("access_token") or token_data.get("token")
                                print(f"\n5. Testing Amazon Ads API...")
                                
                                from amazon_ads_mcp.config.settings import settings
                                
                                headers = {
                                    "Authorization": f"Bearer {amazon_token}",
                                    "Content-Type": "application/json",
                                }
                                
                                # Add client ID if provided
                                if "client_id" in token_data:
                                    headers["Amazon-Advertising-API-ClientId"] = token_data["client_id"]
                                elif "attributes" in token_data and "client_id" in token_data["attributes"]:
                                    headers["Amazon-Advertising-API-ClientId"] = token_data["attributes"]["client_id"]
                                
                                api_response = await client.get(
                                    f"{settings.region_endpoint}/v2/profiles",
                                    headers=headers,
                                )
                                
                                print(f"   API Response: {api_response.status_code}")
                                if api_response.status_code == 200:
                                    print("   ✅ Success! Amazon Ads API works with Openbridge!")
                                    profiles = api_response.json()
                                    print(f"   Found {len(profiles)} profiles")
                                else:
                                    print(f"   Response: {api_response.text}")
                        else:
                            print(f"   Error: {token_response.text}")
            else:
                print(f"   Error: {ri_response.text}")
                
        except Exception as e:
            print(f"   Error: {e}")
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(test_openbridge_jwt())