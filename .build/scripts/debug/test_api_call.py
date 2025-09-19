#!/usr/bin/env python3
"""Test making an actual API call through the server."""

import asyncio
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from amazon_ads_mcp.auth.openbridge_auth import OpenbridgeAuth


async def test_api_call():
    """Test making an API call with Openbridge auth."""
    print("📞 Testing API Call with Openbridge")
    print("=" * 50)
    
    # Initialize Openbridge auth
    openbridge_auth = OpenbridgeAuth(refresh_token="***REDACTED_OPENBRIDGE_TOKEN***")
    
    try:
        # Get identities
        print("\n1. Getting remote identities...")
        identities = await openbridge_auth.get_remote_identities()
        
        # Find Amazon Ads identity
        for identity in identities:
            if identity.get('relationships', {}).get('remote_identity_type', {}).get('data', {}).get('id') == '17':
                remote_id = identity['id']
                name = identity['attributes']['name']
                print(f"\n2. Using identity: {name} (ID: {remote_id})")
                
                # Get token
                print("\n3. Getting Amazon Ads token...")
                token_info = await openbridge_auth.get_amazon_ads_token(remote_id)
                
                print(f"   Access Token: {token_info['access_token'][:50]}...")
                print(f"   Client ID: {token_info['client_id']}")
                
                # Test API call
                import httpx
                async with httpx.AsyncClient() as client:
                    print("\n4. Testing profiles endpoint...")
                    
                    headers = {
                        "Authorization": f"Bearer {token_info['access_token']}",
                        "Amazon-Advertising-API-ClientId": token_info['client_id'],
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
                            
                            if profiles:
                                p = profiles[0]
                                print(f"\n   Profile details:")
                                print(f"   - ID: {p.get('profileId')}")
                                print(f"   - Country: {p.get('countryCode')}")
                                print(f"   - Type: {p.get('accountInfo', {}).get('type')}")
                            
                            print(f"\n✅ Working configuration:")
                            print(f"   Region: {region}")
                            print(f"   Base URL: {base_url}")
                            print(f"   Remote Identity ID: {remote_id}")
                            
                            await openbridge_auth.close()
                            return True
                        else:
                            print(f" - {response.text[:50]}...")
                
                break
        
        await openbridge_auth.close()
        return False
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        await openbridge_auth.close()
        return False


if __name__ == "__main__":
    success = asyncio.run(test_api_call())
    sys.exit(0 if success else 1)