#!/usr/bin/env python3
"""Test MCP tools by making actual API calls."""

import asyncio
import json
import os
from dotenv import load_dotenv

# Enable experimental parser
os.environ["FASTMCP_EXPERIMENTAL_ENABLE_NEW_OPENAPI_PARSER"] = "true"

from src.amazon_ads_mcp.server.main import create_test_account_server

load_dotenv()


async def test_mcp_tools():
    """Test the MCP tools with actual API calls."""
    print("🚀 Testing MCP Tools")
    print("=" * 50)
    
    # Import what we need
    from amazon_ads_mcp.config.settings import settings
    from amazon_ads_mcp.utils.auth import AmazonAdsAuth, AuthenticatedClient
    
    # Initialize authentication
    auth = AmazonAdsAuth(
        client_id=settings.amazon_ads_client_id,
        client_secret=settings.amazon_ads_client_secret,
        refresh_token=settings.amazon_ads_refresh_token,
    )
    
    # Get access token
    await auth.get_access_token()
    print("✅ Got access token")
    
    # Create HTTP client with auth headers
    import httpx
    
    client = httpx.AsyncClient(
        base_url=settings.region_endpoint,
        headers=auth.get_auth_headers(),
        timeout=30.0,
    )
    
    print("\n🔧 Making API Calls:")
    
    # Try to list test accounts (GET /testAccounts)
    print("\n1. Listing test accounts (GET /testAccounts)...")
    try:
        response = await client.get("/testAccounts")
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"   Response: {json.dumps(data, indent=2)}")
        else:
            print(f"   Response: {response.text}")
    except Exception as e:
        print(f"   Error: {e}")
    
    # Try to create a test account (POST /testAccounts)
    print("\n2. Creating a test account (POST /testAccounts)...")
    test_account_data = {
        "countryCode": "US",
        "accountMetaData": {
            "accountType": "VENDOR"
        }
    }
    
    try:
        response = await client.post(
            "/testAccounts",
            json=test_account_data
        )
        print(f"   Status: {response.status_code}")
        if response.status_code in [200, 201]:
            data = response.json()
            print(f"   Response: {json.dumps(data, indent=2)}")
            
            # If we got a requestId, we can check the status
            if "requestId" in data:
                print(f"\n3. Checking account creation status...")
                status_response = await client.get(
                    f"/testAccounts?requestId={data['requestId']}"
                )
                print(f"   Status: {status_response.status_code}")
                if status_response.status_code == 200:
                    status_data = status_response.json()
                    print(f"   Response: {json.dumps(status_data, indent=2)}")
        else:
            print(f"   Response: {response.text}")
    except Exception as e:
        print(f"   Error: {e}")
    
    # Close the client
    await client.aclose()
    
    print("\n✅ Test complete!")


if __name__ == "__main__":
    asyncio.run(test_mcp_tools())