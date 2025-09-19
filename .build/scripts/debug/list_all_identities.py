#!/usr/bin/env python3
"""List all identities and find Amazon Ads ones."""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from amazon_ads_mcp.auth.openbridge_auth import OpenbridgeAuth


async def list_identities():
    """List all identities."""
    print("📋 Listing All Remote Identities")
    print("=" * 50)
    
    openbridge = OpenbridgeAuth("***REDACTED_OPENBRIDGE_TOKEN***")
    
    try:
        identities = await openbridge.get_remote_identities()
        
        print(f"\nFound {len(identities)} identities:")
        
        for identity in identities:
            id_val = identity['id']
            name = identity['attributes']['name']
            type_id = identity.get('relationships', {}).get('remote_identity_type', {}).get('data', {}).get('id')
            
            print(f"\n- ID: {id_val}")
            print(f"  Name: {name}")
            print(f"  Type ID: {type_id}")
            
            if type_id == '17':
                print("  ⭐ This is an Amazon Ads identity")
        
        await openbridge.close()
        
    except Exception as e:
        print(f"Error: {e}")
        await openbridge.close()


if __name__ == "__main__":
    asyncio.run(list_identities())