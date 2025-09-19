#!/usr/bin/env python3
"""
Test script to debug EU region routing issue.
Acts as an MCP client to test if the issue is with the upstream client (Claude Desktop)
or with the server implementation.
"""

import asyncio
import json
import logging
import os
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

import httpx
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Setup logging
logging.basicConfig(
    level=logging.DEBUG if os.getenv("LOG_LEVEL") == "DEBUG" else logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


async def test_direct_api_call():
    """Test direct API call to EU endpoint with proper headers."""
    print("\n" + "="*80)
    print("TEST 1: Direct API Call to EU Endpoint")
    print("="*80)
    
    # Get credentials from environment
    access_token = os.getenv("AMAZON_ADS_ACCESS_TOKEN", "")
    client_id = os.getenv("AMAZON_ADS_CLIENT_ID", "")
    
    if not access_token or not client_id:
        print("❌ Missing AMAZON_ADS_ACCESS_TOKEN or AMAZON_ADS_CLIENT_ID in .env")
        return False
    
    # Test both NA and EU endpoints with same credentials
    endpoints = [
        ("NA", "https://advertising-api.amazon.com"),
        ("EU", "https://advertising-api-eu.amazon.com"),
    ]
    
    results = {}
    
    for region, base_url in endpoints:
        print(f"\nTesting {region} endpoint: {base_url}")
        print("-" * 40)
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{base_url}/v2/profiles",
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "Amazon-Advertising-API-ClientId": client_id,
                        "Accept": "application/json",
                        "Content-Type": "application/json",
                    },
                    timeout=30.0,
                    follow_redirects=False,  # Don't follow redirects to see what's happening
                )
                
                print(f"Status Code: {response.status_code}")
                print(f"Content-Type: {response.headers.get('Content-Type', 'Not specified')}")
                
                # Check if response is JSON or HTML
                content_type = response.headers.get('Content-Type', '').lower()
                
                if 'application/json' in content_type:
                    try:
                        data = response.json()
                        print(f"Response Type: JSON")
                        print(f"Response Preview: {json.dumps(data, indent=2)[:500]}...")
                        results[region] = {"success": True, "type": "json", "status": response.status_code}
                    except json.JSONDecodeError:
                        print(f"Response Type: Invalid JSON")
                        results[region] = {"success": False, "type": "invalid_json", "status": response.status_code}
                elif 'text/html' in content_type:
                    print(f"Response Type: HTML (Suspicious! API should return JSON)")
                    print(f"HTML Preview: {response.text[:200]}...")
                    results[region] = {"success": False, "type": "html", "status": response.status_code}
                else:
                    print(f"Response Type: {content_type}")
                    print(f"Response Preview: {response.text[:200]}...")
                    results[region] = {"success": False, "type": content_type, "status": response.status_code}
                    
        except httpx.HTTPError as e:
            print(f"❌ HTTP Error: {e}")
            results[region] = {"success": False, "error": str(e)}
        except Exception as e:
            print(f"❌ Unexpected Error: {e}")
            results[region] = {"success": False, "error": str(e)}
    
    # Compare results
    print("\n" + "="*80)
    print("COMPARISON")
    print("="*80)
    
    if results.get("NA", {}).get("success") and not results.get("EU", {}).get("success"):
        print("🔍 SMOKING GUN: NA works but EU fails with same credentials!")
        print("   This indicates an EU-specific routing/proxy issue.")
        if results.get("EU", {}).get("type") == "html":
            print("   EU is returning HTML instead of JSON - likely hitting wrong endpoint/CDN")
    elif not results.get("NA", {}).get("success") and not results.get("EU", {}).get("success"):
        print("❌ Both regions failed - check your credentials")
    elif results.get("NA", {}).get("success") and results.get("EU", {}).get("success"):
        print("✅ Both regions work! Issue might be in MCP server routing")
    
    return results


async def test_mcp_server_call():
    """Test calling the MCP server with region override."""
    print("\n" + "="*80)
    print("TEST 2: MCP Server Call with Region Override")
    print("="*80)
    
    # Check if MCP server is running
    mcp_port = 9080  # User specified port
    mcp_url = f"http://localhost:{mcp_port}"
    
    print(f"Testing MCP server at {mcp_url}")
    
    try:
        async with httpx.AsyncClient() as client:
            # First, check if server is running
            try:
                health = await client.get(f"{mcp_url}/health", timeout=5.0)
                if health.status_code != 200:
                    print(f"❌ MCP server not responding properly at {mcp_url}")
                    print("   Please ensure the MCP server is running: uv run mcp_server.py")
                    return False
            except:
                print(f"❌ Cannot connect to MCP server at {mcp_url}")
                print("   Please ensure the MCP server is running: uv run mcp_server.py")
                return False
            
            print("✅ MCP server is running")
            
            # Test the region override and profiles call
            # This simulates what Claude Desktop would do
            
            # Set region override to EU
            print("\nSetting region override to EU...")
            override_response = await client.post(
                f"{mcp_url}/tools/call",
                json={
                    "name": "set_region_override",
                    "arguments": {"region": "eu"}
                },
                timeout=10.0
            )
            print(f"Region override response: {override_response.status_code}")
            
            # Check routing state
            print("\nChecking routing state...")
            routing_response = await client.post(
                f"{mcp_url}/tools/call",
                json={
                    "name": "show_routing_state",
                    "arguments": {}
                },
                timeout=10.0
            )
            if routing_response.status_code == 200:
                routing_data = routing_response.json()
                print(f"Routing state: {json.dumps(routing_data, indent=2)}")
            
            # Call profiles endpoint
            print("\nCalling ap_listProfiles...")
            profiles_response = await client.post(
                f"{mcp_url}/tools/call",
                json={
                    "name": "ap_listProfiles",
                    "arguments": {}
                },
                timeout=30.0
            )
            
            print(f"Profiles response status: {profiles_response.status_code}")
            if profiles_response.status_code == 200:
                profiles_data = profiles_response.json()
                print(f"Profiles response preview: {json.dumps(profiles_data, indent=2)[:500]}...")
                return True
            else:
                print(f"❌ Failed to get profiles: {profiles_response.text[:500]}")
                return False
                
    except Exception as e:
        print(f"❌ Error testing MCP server: {e}")
        return False


async def test_with_auth_manager():
    """Test using the auth manager directly to ensure proper header construction."""
    print("\n" + "="*80)
    print("TEST 3: Auth Manager Header Construction")
    print("="*80)
    
    try:
        from src.amazon_ads_mcp.auth.manager import AuthManager
        from src.amazon_ads_mcp.config.settings import Settings
        
        auth_manager = AuthManager()
        
        # Check if we have an active identity
        identities = auth_manager.list_identities()
        if not identities:
            print("❌ No identities configured in auth manager")
            return False
        
        print(f"Found {len(identities)} identities")
        
        # Find an EU identity or set one active
        eu_identity = None
        for identity in identities:
            if identity.get("region") == "eu":
                eu_identity = identity
                break
        
        if eu_identity:
            print(f"Found EU identity: {eu_identity['name']} (ID: {eu_identity['id']})")
            auth_manager.set_active_identity(eu_identity['id'])
        else:
            print("⚠️  No EU identity found, using first available")
            auth_manager.set_active_identity(identities[0]['id'])
        
        # Get headers for EU
        headers = auth_manager.get_headers()
        print("\nGenerated headers:")
        for key, value in headers.items():
            if "token" in key.lower() or "authorization" in key.lower():
                print(f"  {key}: [REDACTED]")
            else:
                print(f"  {key}: {value}")
        
        # Test with these headers
        base_url = "https://advertising-api-eu.amazon.com"
        print(f"\nTesting {base_url}/v2/profiles with auth manager headers...")
        
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{base_url}/v2/profiles",
                headers=headers,
                timeout=30.0,
                follow_redirects=False
            )
            
            print(f"Status Code: {response.status_code}")
            print(f"Content-Type: {response.headers.get('Content-Type', 'Not specified')}")
            
            content_type = response.headers.get('Content-Type', '').lower()
            if 'application/json' in content_type:
                print("✅ Got JSON response from EU endpoint with auth manager headers")
                return True
            elif 'text/html' in content_type:
                print("❌ Got HTML response - routing/proxy issue confirmed")
                return False
            else:
                print(f"❓ Unexpected content type: {content_type}")
                return False
                
    except ImportError as e:
        print(f"❌ Cannot import auth manager: {e}")
        return False
    except Exception as e:
        print(f"❌ Error testing auth manager: {e}")
        return False


async def main():
    """Run all tests."""
    print("\n" + "="*80)
    print("AMAZON ADS API - EU REGION ROUTING TEST")
    print("="*80)
    print(f"Environment: {os.getenv('ENVIRONMENT', 'Not set')}")
    print(f"Log Level: {os.getenv('LOG_LEVEL', 'INFO')}")
    print(f"Region Setting: {os.getenv('AMAZON_ADS_REGION', 'Not set')}")
    
    # Run tests
    results = {}
    
    # Test 1: Direct API calls
    results['direct_api'] = await test_direct_api_call()
    
    # Test 2: MCP Server calls (optional - only if server is running)
    # Uncomment to test MCP server
    # results['mcp_server'] = await test_mcp_server_call()
    
    # Test 3: Auth Manager
    results['auth_manager'] = await test_with_auth_manager()
    
    # Summary
    print("\n" + "="*80)
    print("TEST SUMMARY")
    print("="*80)
    
    if isinstance(results.get('direct_api'), dict):
        na_works = results['direct_api'].get('NA', {}).get('success', False)
        eu_works = results['direct_api'].get('EU', {}).get('success', False)
        
        if na_works and not eu_works:
            print("🔍 DIAGNOSIS: EU endpoint issue confirmed!")
            print("   - NA endpoint works with your credentials")
            print("   - EU endpoint fails with same credentials")
            print("   - This is NOT a code issue in your MCP server")
            print("\n   Possible causes:")
            print("   1. Network/firewall blocking EU domain")
            print("   2. DNS resolution issue for advertising-api-eu.amazon.com")
            print("   3. VPN/proxy interfering with EU routing")
            print("   4. Token doesn't have EU marketplace scope")
            print("\n   Next steps:")
            print("   1. Try from a different network/VPN")
            print("   2. Check DNS resolution: nslookup advertising-api-eu.amazon.com")
            print("   3. Contact Amazon Ads API support about EU access")
        elif na_works and eu_works:
            print("✅ Both endpoints work! Issue might be in upstream client (Claude Desktop)")
        elif not na_works and not eu_works:
            print("❌ Neither endpoint works - check your credentials in .env")
    
    print("\n" + "="*80)


if __name__ == "__main__":
    asyncio.run(main())