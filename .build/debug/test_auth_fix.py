#!/usr/bin/env python3
"""
Test script to verify the auth header fix for EU endpoint.
"""

import asyncio
import os
import sys
from pathlib import Path

# Add project to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

# Set debug logging to see headers
os.environ["LOG_LEVEL"] = "DEBUG"

from amazon_ads_mcp.server.mcp_server import AuthenticatedClient
from amazon_ads_mcp.auth.manager import AuthManager


async def test_auth_headers():
    """Test that auth headers are properly injected."""
    
    print("="*80)
    print("TESTING AUTH HEADER INJECTION FIX")
    print("="*80)
    
    # Initialize auth manager
    auth_manager = AuthManager()
    
    # Check if we have an active identity
    try:
        active = auth_manager.get_active_identity()
        if active:
            print(f"✅ Active identity found: {active.id}")
        else:
            print("❌ No active identity - setting one...")
            # Try to set identity from environment
            identity_id = os.getenv("OPENBRIDGE_REMOTE_IDENTITY_ID", "12927")
            await auth_manager.set_active_identity(identity_id)
            print(f"Set identity: {identity_id}")
    except Exception as e:
        print(f"⚠️  Identity check error: {e}")
        print("Attempting to set identity 12927...")
        await auth_manager.set_active_identity("12927")
    
    # Create authenticated client
    print("\nCreating authenticated client...")
    client = AuthenticatedClient(
        base_url="https://advertising-api-eu.amazon.com",
        auth_manager=auth_manager,
        timeout=30.0
    )
    
    print("\nMaking request to EU profiles endpoint...")
    print("Watch for debug logs showing headers being added...")
    print("-" * 40)
    
    try:
        response = await client.get("/v2/profiles")
        
        print("-" * 40)
        print(f"\n📥 Response Status: {response.status_code}")
        
        content_type = response.headers.get("content-type", "").lower()
        if response.status_code == 200 and "application/json" in content_type:
            print("✅ SUCCESS! Got JSON response from EU endpoint")
            print("   Headers were properly injected!")
            data = response.json()
            print(f"   Found {len(data) if isinstance(data, list) else 1} profiles")
        elif response.status_code == 404:
            if "text/html" in content_type:
                print("❌ STILL BROKEN: Got HTML 404")
                print("   Headers may not be injected properly")
                print(f"   Response preview: {response.text[:200]}")
            else:
                print("❌ Got 404 but it's JSON (API error, not routing issue)")
                print(f"   Response: {response.text[:200]}")
        else:
            print(f"❓ Unexpected response: {response.status_code}")
            print(f"   Content type: {content_type}")
            print(f"   Response: {response.text[:200]}")
            
    except Exception as e:
        print(f"❌ Request failed: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        await client.aclose()
    
    print("\n" + "="*80)
    print("DIAGNOSIS")
    print("="*80)
    print("""
Check the debug logs above for:
1. "Adding auth headers to request:" - Should show headers being added
2. "Final request headers:" - Should include Authorization and ClientId
3. Response status - Should be 200 with JSON, not 404 with HTML

If headers are shown but still getting 404, the issue is elsewhere.
If headers are NOT shown, the auth manager isn't providing them.
""")


if __name__ == "__main__":
    asyncio.run(test_auth_headers())