#!/usr/bin/env python3
"""Final diagnostic to identify the issue."""

import asyncio
import json
import base64
from dotenv import load_dotenv
from amazon_ads_mcp.config.settings import settings
from amazon_ads_mcp.utils.auth import AmazonAdsAuth

load_dotenv()


async def final_diagnostic():
    """Run final diagnostic checks."""
    print("🔍 Final Diagnostic Check")
    print("=" * 50)
    
    print("\n1. Current Configuration:")
    print(f"   Client ID: {settings.amazon_ads_client_id}")
    print(f"   Client ID length: {len(settings.amazon_ads_client_id)}")
    print(f"   Has Client Secret: {'Yes' if settings.amazon_ads_client_secret else 'No'}")
    print(f"   Refresh Token starts with: {settings.amazon_ads_refresh_token[:30]}...")
    print(f"   Refresh Token length: {len(settings.amazon_ads_refresh_token)}")
    
    # Get token
    auth = AmazonAdsAuth(
        client_id=settings.amazon_ads_client_id,
        client_secret=settings.amazon_ads_client_secret,
        refresh_token=settings.amazon_ads_refresh_token,
    )
    
    await auth.get_access_token()
    print(f"\n2. Access Token Analysis:")
    print(f"   Token obtained: Yes")
    print(f"   Token starts with: {auth.access_token[:30]}...")
    
    # Try to decode if JWT
    if '.' in auth.access_token:
        try:
            parts = auth.access_token.split('.')
            if len(parts) >= 2:
                payload = base64.urlsafe_b64decode(parts[1] + '==')
                claims = json.loads(payload)
                print(f"   Token claims: {json.dumps(claims, indent=2)}")
        except:
            print("   Token type: Opaque (not JWT)")
    else:
        print("   Token type: Opaque Amazon token")
    
    print("\n\n❓ Questions to verify:")
    print("\n1. In your WORKING codebase:")
    print("   - What is the Client ID? (Is it the same as above?)")
    print("   - What headers are sent with API requests?")
    print("   - What is the exact API endpoint used?")
    print("   - Is there any proxy or special network configuration?")
    
    print("\n2. About this Client ID:")
    print("   - When was it registered for API access?")
    print("   - Is it approved for PRODUCTION or just SANDBOX?")
    print("   - What API programs was it approved for?")
    
    print("\n3. About the accounts:")
    print("   - Do these Amazon accounts have Seller Central or Vendor Central access?")
    print("   - Have they created advertising campaigns before?")
    print("   - What marketplace are they in (US, UK, etc)?")
    
    print("\n\n🎯 Most likely issues:")
    print("1. This Client ID is different from your working one")
    print("2. This Client ID only has sandbox access, not production")
    print("3. The accounts don't have advertising profiles")
    print("4. The OAuth didn't include advertising scopes")


if __name__ == "__main__":
    asyncio.run(final_diagnostic())