#!/usr/bin/env python3
"""
Debug script to capture and compare headers between working curl and MCP server requests.
"""

import asyncio
import json
import httpx
import logging
from unittest.mock import patch, MagicMock

# Setup logging to see all HTTP details
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Disable httpx's default logging to reduce noise
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)


async def test_direct_with_your_credentials():
    """Test with the exact credentials that work in curl."""
    
    print("="*80)
    print("TESTING WITH YOUR WORKING CREDENTIALS")
    print("="*80)
    
    # Your working credentials from curl
    access_token = "Atza|IwEBIKYJxxG-GKvk7m6A7wn_klhKt7_bZNh71zcp8AQ19sa0O5jXyEZIbLznHdb0NYT1_hFGJAWsdfZy3c_iOBZMvtuq5iT-KECM__0WWfAxPPZKnX-gIfhkRe2FMUMEF6R2Qkrs86b9l79qCastX0_MVqYjqeGlc9YBB0BXFFTmbvmk040TQMw63UukMHaCPiM7HZwLSQNLWwjNunDTDJGKQDwOpx2pPhtKhxQ2GycIBJyNVxwUoEpw6nOLdYSI6AlWzmcdeBOQe4PbnzCCV9_7XXg-ghfrnQRSHnV1aY8j8H7WNxr21pO8G_8TrtlNogSHIbo7U0fdepTVFgJoPqvnJ4jar6P5sXf8KI7vVGDlP7s1hKHD7qvB8w-NWg1mIJy74MKlgLiqFfFfTz1uUlu7wbl07QOhglhApYrHnRd7TEmJaOyCBm4QPl3KfFxSfQ9tWwV8Xmy8_vmbmfNzuCkazzoOVyipSp__lz1vHPrQBIkU80kMXz5bW5Jxe5oIM3zS8enWRZgifveJJCL1Ed700N2pzANod4_yj5BcFN9rvW9x7bUZ0px7-tRHTg3FnefQptPuYGnz7cGCFu6O0649Ncli"
    client_id = "amzn1.application-oa2-client.2828e4a214e4478797b9ca3d3baeb839"
    
    # Test EU endpoint
    url = "https://advertising-api-eu.amazon.com/v2/profiles"
    
    headers = {
        "amazon-advertising-api-clientid": client_id,
        "authorization": f"Bearer {access_token}",
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    
    print("\nHeaders being sent:")
    for k, v in headers.items():
        if "authorization" in k.lower():
            print(f"  {k}: Bearer [REDACTED...]")
        else:
            print(f"  {k}: {v}")
    
    print(f"\nURL: {url}")
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                url,
                headers=headers,
                timeout=30.0,
                follow_redirects=False
            )
            
            print(f"\nResponse Status: {response.status_code}")
            print(f"Response Headers: {dict(response.headers)}")
            
            content_type = response.headers.get("content-type", "").lower()
            if "application/json" in content_type:
                print("✅ Got JSON response!")
                data = response.json()
                print(f"Response preview: {json.dumps(data, indent=2)[:500]}")
            elif "text/html" in content_type:
                print("❌ Got HTML response (404 page)")
                print(f"HTML preview: {response.text[:300]}")
            else:
                print(f"Response type: {content_type}")
                print(f"Response: {response.text[:300]}")
                
    except Exception as e:
        print(f"❌ Error: {e}")


async def test_through_mcp_server():
    """Test the same request through MCP server to see what headers it sends."""
    
    print("\n" + "="*80)
    print("TESTING THROUGH MCP SERVER")
    print("="*80)
    
    # Import MCP server components
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent / "src"))
    
    try:
        from amazon_ads_mcp.server.mcp_server import AuthenticatedClient
        from amazon_ads_mcp.auth.manager import AuthManager
        
        print("\n1. Setting up MCP authenticated client...")
        
        # Create auth manager
        auth_manager = AuthManager()
        
        # Create a mock authenticated client to capture headers
        class DebugAuthenticatedClient(AuthenticatedClient):
            async def send(self, request, **kwargs):
                print("\n📤 MCP Server is sending request:")
                print(f"   URL: {request.url}")
                print("   Headers:")
                for k, v in request.headers.items():
                    if "authorization" in k.lower() or "token" in k.lower():
                        print(f"     {k}: [REDACTED]")
                    else:
                        print(f"     {k}: {v}")
                
                # Call parent
                return await super().send(request, **kwargs)
        
        # Create client with auth manager
        client = DebugAuthenticatedClient(
            base_url="https://advertising-api-eu.amazon.com",
            auth_manager=auth_manager,
            timeout=30.0
        )
        
        print("\n2. Making request through MCP client...")
        
        response = await client.get("/v2/profiles")
        
        print(f"\n📥 Response Status: {response.status_code}")
        content_type = response.headers.get("content-type", "").lower()
        
        if "application/json" in content_type:
            print("✅ Got JSON response through MCP!")
        elif "text/html" in content_type:
            print("❌ Got HTML 404 through MCP")
            print(f"Preview: {response.text[:200]}")
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("   Make sure you're running from the project root")
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()


async def main():
    print("\n🔍 HEADER DEBUGGING TOOL")
    print("This will help identify why the MCP server gets 404 while curl works\n")
    
    # Test 1: Direct with your credentials
    await test_direct_with_your_credentials()
    
    # Test 2: Through MCP server
    await test_through_mcp_server()
    
    print("\n" + "="*80)
    print("ANALYSIS")
    print("="*80)
    print("""
If the direct test works but MCP fails, check:
1. Header names (case sensitive?)
2. Authorization format (Bearer with capital B)
3. Additional headers MCP might be adding/removing
4. URL construction differences
""")


if __name__ == "__main__":
    asyncio.run(main())