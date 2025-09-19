#!/usr/bin/env python3
"""Test script for direct Amazon Ads API authentication (BYOA).

This script tests the "Bring Your Own API" pathway that allows users
to provide their own Amazon Ads API credentials directly.
"""

import asyncio
import os
import sys
from datetime import datetime

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from amazon_ads_mcp.auth.manager import get_auth_manager
from amazon_ads_mcp.config.settings import Settings


async def test_direct_auth():
    """Test direct authentication pathway."""
    print("=" * 60)
    print("Testing Direct Amazon Ads API Authentication (BYOA)")
    print("=" * 60)
    
    # Check environment variables
    required_vars = ["AD_API_CLIENT_ID", "AD_API_CLIENT_SECRET", "AD_API_REFRESH_TOKEN"]
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    
    if missing_vars:
        print("\n❌ Missing required environment variables:")
        for var in missing_vars:
            print(f"   - {var}")
        print("\nTo use direct authentication, set these environment variables:")
        print("   export AD_API_CLIENT_ID='your-client-id'")
        print("   export AD_API_CLIENT_SECRET='your-client-secret'")
        print("   export AD_API_REFRESH_TOKEN='your-refresh-token'")
        print("   export AD_API_PROFILE_ID='your-profile-id' (optional)")
        return False
    
    print("\n✅ Required environment variables found:")
    print(f"   - AD_API_CLIENT_ID: {'*' * 10}{os.getenv('AD_API_CLIENT_ID')[-4:]}")
    print(f"   - AD_API_CLIENT_SECRET: {'*' * 10}")
    print(f"   - AD_API_REFRESH_TOKEN: {'*' * 10}")
    
    profile_id = os.getenv("AD_API_PROFILE_ID")
    if profile_id:
        print(f"   - AD_API_PROFILE_ID: {profile_id}")
    
    # Initialize settings and check auth method
    settings = Settings()
    print(f"\n📋 Configuration:")
    print(f"   - Auth method: {settings.auth_method}")
    print(f"   - Region: {settings.amazon_ads_region}")
    print(f"   - Endpoint: {settings.region_endpoint}")
    
    if settings.auth_method != "direct":
        print("\n⚠️  Auth method is not 'direct'. The system should auto-detect")
        print("    when direct credentials are provided.")
    
    try:
        # Get auth manager
        auth_manager = get_auth_manager()
        print("\n✅ Auth manager initialized successfully")
        
        # List identities (should return synthetic identity for direct auth)
        print("\n🔍 Listing identities...")
        identities = await auth_manager.list_identities()
        
        for identity in identities:
            print(f"\n   Identity found:")
            print(f"   - ID: {identity.id}")
            print(f"   - Type: {identity.type}")
            if hasattr(identity, 'attributes') and identity.attributes:
                print(f"   - Attributes:")
                for key, value in identity.attributes.items():
                    if key != "client_secret":  # Don't print secrets
                        print(f"      • {key}: {value}")
        
        # Set active identity
        if identities:
            identity_id = identities[0].id
            print(f"\n🔐 Setting active identity: {identity_id}")
            await auth_manager.set_active_identity(identity_id)
            
            # Get credentials
            print("\n🎫 Getting credentials...")
            credentials = await auth_manager.get_active_credentials()
            
            print(f"\n✅ Credentials obtained successfully:")
            print(f"   - Identity ID: {credentials.identity_id}")
            print(f"   - Expires at: {credentials.expires_at}")
            print(f"   - Base URL: {credentials.base_url}")
            print(f"   - Headers present: {list(credentials.headers.keys())}")
            
            # Check token validity
            time_until_expiry = credentials.expires_at - datetime.now()
            print(f"   - Token valid for: {time_until_expiry.total_seconds():.0f} seconds")
            
            print("\n✅ Direct authentication test completed successfully!")
            return True
        else:
            print("\n❌ No identities found")
            return False
            
    except Exception as e:
        print(f"\n❌ Error during authentication test: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        # Cleanup
        if 'auth_manager' in locals():
            await auth_manager.close()


async def main():
    """Run the test."""
    success = await test_direct_auth()
    
    print("\n" + "=" * 60)
    if success:
        print("✅ BYOA Authentication Pathway: WORKING")
        print("\nYou can now use your own Amazon Ads API credentials directly!")
        print("The system will automatically detect and use them.")
    else:
        print("❌ BYOA Authentication Pathway: FAILED")
        print("\nPlease check the error messages above and ensure your")
        print("credentials are valid.")
    print("=" * 60)
    
    return 0 if success else 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)