#!/usr/bin/env python3
"""Test script to verify Amazon Ads API connectivity."""

import asyncio
import json
import os
from pathlib import Path

import httpx
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


async def test_api_connection():
    """Test the Amazon Ads API connection."""
    # Get credentials from environment
    client_id = os.getenv("AMAZON_ADS_CLIENT_ID")
    client_secret = os.getenv("AMAZON_ADS_CLIENT_SECRET")
    refresh_token = os.getenv("AMAZON_ADS_REFRESH_TOKEN")
    
    if not all([client_id, client_secret, refresh_token]):
        print("❌ Missing credentials. Please set:")
        print("   - AMAZON_ADS_CLIENT_ID")
        print("   - AMAZON_ADS_CLIENT_SECRET")
        print("   - AMAZON_ADS_REFRESH_TOKEN")
        return
    
    print("✅ Credentials found")
    
    # Get access token
    print("\n📡 Getting access token...")
    token_url = "https://api.amazon.com/auth/o2/token"
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                token_url,
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                    "client_id": client_id,
                    "client_secret": client_secret,
                },
            )
            response.raise_for_status()
            token_data = response.json()
            access_token = token_data["access_token"]
            print("✅ Access token obtained")
            
        except httpx.HTTPStatusError as e:
            print(f"❌ Failed to get access token: {e.response.status_code}")
            print(f"   Response: {e.response.text}")
            return
        except Exception as e:
            print(f"❌ Error getting access token: {e}")
            return
    
    # Test API endpoint
    print("\n📡 Testing Test Account API...")
    # Try production API since test environment is down
    base_url = "https://advertising-api.amazon.com"  # Production environment
    
    async with httpx.AsyncClient(
        base_url=base_url,
        headers={
            "Authorization": f"Bearer {access_token}",
            "Amazon-Advertising-API-ClientId": client_id,
            "Content-Type": "application/json",
        },
        timeout=30.0,
    ) as client:
        # Try to get existing test accounts
        try:
            response = await client.get("/testAccounts")
            print(f"✅ API Response Status: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                print(f"✅ Successfully connected to Amazon Ads API")
                print(f"   Response: {json.dumps(data, indent=2)}")
            else:
                print(f"⚠️  Unexpected status: {response.status_code}")
                print(f"   Response: {response.text}")
                
        except httpx.HTTPStatusError as e:
            print(f"❌ API Error: {e.response.status_code}")
            print(f"   Response: {e.response.text}")
        except Exception as e:
            print(f"❌ Connection Error: {e}")
    
    print("\n✅ Test complete!")


async def test_create_account():
    """Test creating a test account (optional)."""
    print("\n📝 To create a test account, you would POST to /testAccounts with:")
    print(json.dumps({
        "countryCode": "US",
        "accountMetaData": {
            "accountType": "VENDOR"
        }
    }, indent=2))
    print("\nThis would return a requestId to track the account creation.")


if __name__ == "__main__":
    print("🚀 Amazon Ads API Connection Test")
    print("=" * 50)
    
    asyncio.run(test_api_connection())
    asyncio.run(test_create_account())