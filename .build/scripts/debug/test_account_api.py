#!/usr/bin/env python3
"""Test the Test Account API with correct authentication."""

import asyncio
import json
import httpx
from dotenv import load_dotenv
from amazon_ads_mcp.config.settings import settings

load_dotenv()


async def test_account_api():
    """Test the Test Account API endpoints."""
    print("🚀 Testing Amazon Ads Test Account API")
    print("=" * 50)
    
    # The test account API only needs the Client ID header, not Bearer token
    headers = {
        "Amazon-Advertising-API-ClientId": settings.amazon_ads_client_id,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    
    print("\nUsing headers:")
    for k, v in headers.items():
        print(f"  {k}: {v}")
    
    # Use the production endpoint (test accounts are created in production)
    base_url = "https://advertising-api.amazon.com"
    
    async with httpx.AsyncClient(base_url=base_url, timeout=30.0) as client:
        # 1. Try to get existing test accounts
        print("\n1. Getting existing test accounts...")
        try:
            response = await client.get(
                "/testAccounts",
                headers=headers
            )
            print(f"   Status: {response.status_code}")
            print(f"   Response: {response.text}")
            
            if response.status_code == 200:
                accounts = response.json()
                if accounts:
                    print("\n   Existing test accounts:")
                    for account in accounts:
                        print(f"   - Country: {account.get('countryCode')}")
                        print(f"     Type: {account.get('accountType')}")
                        print(f"     Status: {account.get('status')}")
                        print(f"     ID: {account.get('id')}")
                        print()
                else:
                    print("   No test accounts found")
                    
        except Exception as e:
            print(f"   Error: {e}")
        
        # 2. Try to create a test account
        print("\n2. Creating a test account...")
        test_account_data = {
            "countryCode": "US",
            "accountType": "VENDOR"
        }
        
        print(f"   Request body: {json.dumps(test_account_data, indent=2)}")
        
        try:
            response = await client.post(
                "/testAccounts",
                headers=headers,
                json=test_account_data
            )
            print(f"   Status: {response.status_code}")
            print(f"   Response: {response.text}")
            
            if response.status_code == 200:
                result = response.json()
                request_id = result.get("requestId")
                print(f"   ✅ Success! Request ID: {request_id}")
                
                # 3. Check the status of the request
                if request_id:
                    print(f"\n3. Checking account creation status...")
                    await asyncio.sleep(2)  # Wait a bit
                    
                    response = await client.get(
                        f"/testAccounts?requestId={request_id}",
                        headers=headers
                    )
                    print(f"   Status: {response.status_code}")
                    if response.status_code == 200:
                        status_data = response.json()
                        print(f"   Response: {json.dumps(status_data, indent=2)}")
                        
            elif response.status_code == 422:
                # This might mean we already have a test account for this country/type
                print("   ⚠️  422 Error - You may already have a test account for this marketplace/type")
                
        except Exception as e:
            print(f"   Error: {e}")
    
    print("\n📌 Notes:")
    print("- Test Account API doesn't require Bearer token authentication")
    print("- Only requires Amazon-Advertising-API-ClientId header")
    print("- You can create 1 test account per marketplace/type combination")
    print("- Test accounts are for testing API integration")


if __name__ == "__main__":
    asyncio.run(test_account_api())