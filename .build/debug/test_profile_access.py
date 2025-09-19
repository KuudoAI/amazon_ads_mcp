#!/usr/bin/env python3
"""
Test to verify which profiles are accessible in which regions.
"""

import asyncio
import os
import sys
from pathlib import Path

# Add project to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

# Set debug logging
os.environ["LOG_LEVEL"] = "INFO"
os.environ["OPENBRIDGE_REMOTE_IDENTITY_ID"] = "12927"

from amazon_ads_mcp.server.mcp_server import AuthenticatedClient
from amazon_ads_mcp.auth.manager import AuthManager


async def test_profile_access():
    """Test profile access across regions."""
    
    print("="*80)
    print("TESTING PROFILE ACCESS ACROSS REGIONS")
    print("="*80)
    
    # Initialize auth manager
    auth_manager = AuthManager()
    
    # Set active identity
    await auth_manager.set_active_identity("12927")
    print("✅ Identity 12927 set as active")
    
    # The profile ID you're trying to access
    profile_id = "3433820656974170"
    
    # Test different regions
    regions = [
        ("NA", "https://advertising-api.amazon.com"),
        ("EU", "https://advertising-api-eu.amazon.com"),
        ("FE", "https://advertising-api-fe.amazon.com"),
    ]
    
    for region_name, base_url in regions:
        print(f"\n{'='*40}")
        print(f"Testing {region_name} region: {base_url}")
        print('='*40)
        
        # Create client for this region
        client = AuthenticatedClient(
            base_url=base_url,
            auth_manager=auth_manager,
            timeout=30.0
        )
        
        try:
            # First, list all profiles in this region
            print(f"\n1. Listing profiles in {region_name}...")
            response = await client.get("/v2/profiles")
            
            if response.status_code == 200:
                profiles = response.json()
                print(f"   ✅ Found {len(profiles)} profiles in {region_name}")
                
                # Check if our specific profile is in this region
                profile_ids = [str(p.get("profileId")) for p in profiles]
                if profile_id in profile_ids:
                    print(f"   ✅ Profile {profile_id} EXISTS in {region_name}!")
                    
                    # Show the profile details
                    profile = next(p for p in profiles if str(p.get("profileId")) == profile_id)
                    print(f"      Country: {profile.get('countryCode')}")
                    print(f"      Currency: {profile.get('currencyCode')}")
                    print(f"      Account: {profile.get('accountInfo', {}).get('name')}")
                else:
                    print(f"   ❌ Profile {profile_id} NOT FOUND in {region_name}")
                    
                # List first few profile IDs
                if profiles:
                    print(f"\n   Available profiles in {region_name}:")
                    for p in profiles[:5]:
                        pid = p.get("profileId")
                        country = p.get("countryCode", "??")
                        name = p.get("accountInfo", {}).get("name", "Unknown")
                        print(f"      - {pid} ({country}) - {name}")
                    if len(profiles) > 5:
                        print(f"      ... and {len(profiles) - 5} more")
                        
            else:
                print(f"   ❌ Failed to list profiles: {response.status_code}")
                print(f"      Response: {response.text[:200]}")
                
            # Now try to access the specific profile
            print(f"\n2. Trying to access profile {profile_id} directly...")
            response = await client.get(f"/v2/profiles/{profile_id}")
            
            if response.status_code == 200:
                print(f"   ✅ Successfully accessed profile {profile_id} in {region_name}")
                data = response.json()
                print(f"      Country: {data.get('countryCode')}")
                print(f"      Currency: {data.get('currencyCode')}")
            elif response.status_code == 404:
                print(f"   ❌ Profile {profile_id} returns 404 in {region_name}")
                print(f"      This profile doesn't exist or you don't have access in this region")
            else:
                print(f"   ❌ Error {response.status_code} accessing profile")
                print(f"      Response: {response.text[:200]}")
                
        except Exception as e:
            print(f"   ❌ Error testing {region_name}: {e}")
        finally:
            await client.aclose()
    
    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)
    print(f"""
Profile {profile_id} accessibility:
- If it shows in one region but not others, it's region-specific
- If it shows in listings but 404 on direct access, there's a permission issue
- If it doesn't show anywhere, it might not exist or you don't have access

Your identity (12927) is configured for EU region, so profiles from other
regions might not be accessible even if they exist.
""")


if __name__ == "__main__":
    asyncio.run(test_profile_access())