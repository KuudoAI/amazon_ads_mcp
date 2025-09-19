#!/usr/bin/env python3
"""Test OpenBridge authentication."""

import asyncio
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from amazon_ads_mcp.auth.manager import get_auth_manager
import logging

logging.basicConfig(level=logging.INFO)

async def test():
    print("Testing OpenBridge authentication...")
    
    try:
        auth_manager = get_auth_manager()
        print(f"Auth manager initialized with {type(auth_manager.provider).__name__}")
        
        print("\nListing identities...")
        identities = await auth_manager.list_identities()
        print(f"Found {len(identities)} identities")
        
        for i, identity in enumerate(identities[:5]):  # Show first 5
            print(f"  {i+1}. ID: {identity.id}, Type: {identity.type}")
            if hasattr(identity, 'attributes'):
                attrs = getattr(identity, 'attributes', {})
                if attrs:
                    print(f"     Name: {attrs.get('name', 'N/A')}")
        
        return True
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        if 'auth_manager' in locals():
            await auth_manager.close()

if __name__ == "__main__":
    success = asyncio.run(test())
    sys.exit(0 if success else 1)