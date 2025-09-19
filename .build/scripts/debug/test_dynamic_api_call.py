#!/usr/bin/env python3
"""Test actual API calls through the dynamic MCP server."""

import asyncio
import json
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def test_api_calls():
    """Test API calls through the dynamic server."""
    server_params = StdioServerParameters(
        command=".venv/bin/python",
        args=["-m", "amazon_ads_mcp.server.main_dynamic"],
        env=None
    )
    
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            
            print("\n🧪 Testing Amazon Ads API through dynamic MCP server")
            print("=" * 60)
            
            # Test 1: List profiles
            print("\n📋 Test 1: Listing advertising profiles")
            try:
                result = await session.call_tool(
                    "listProfiles",
                    arguments={
                        # The auth headers are added automatically by our middleware
                        # No need to pass Amazon-Advertising-API-ClientId
                    }
                )
                
                if result.content:
                    for content in result.content:
                        if content.type == "text":
                            try:
                                data = json.loads(content.text)
                                print(f"✅ Successfully retrieved {len(data)} profiles:")
                                for idx, profile in enumerate(data[:3]):  # Show first 3
                                    print(f"   {idx+1}. Profile ID: {profile.get('profileId')}")
                                    print(f"      Country: {profile.get('countryCode')}")
                                    print(f"      Currency: {profile.get('currencyCode')}")
                                    print(f"      Marketplace: {profile.get('accountInfo', {}).get('marketplaceStringId', 'N/A')}")
                            except json.JSONDecodeError:
                                print(f"Response: {content.text[:500]}...")
                else:
                    print("❌ No content in response")
                    
            except Exception as e:
                print(f"❌ Error: {e}")
            
            # Test 2: Get test accounts
            print("\n📋 Test 2: Checking test accounts")
            try:
                result = await session.call_tool(
                    "listTestAccountsAction",
                    arguments={}
                )
                
                if result.content:
                    for content in result.content:
                        if content.type == "text":
                            try:
                                data = json.loads(content.text)
                                if isinstance(data, list):
                                    print(f"✅ Found {len(data)} test accounts")
                                else:
                                    print(f"✅ Test accounts response: {content.text[:200]}...")
                            except:
                                print(f"Response: {content.text[:200]}...")
                else:
                    print("❌ No content in response")
                    
            except Exception as e:
                print(f"❌ Error: {e}")
            
            # Test 3: List campaigns
            print("\n📋 Test 3: Listing Sponsored Products campaigns")
            try:
                # Use the first profile ID from earlier
                result = await session.call_tool(
                    "ListSponsoredProductsCampaigns",
                    arguments={
                        "body": {
                            "stateFilter": {"include": ["ENABLED"]},
                            "maxResults": 5
                        }
                    }
                )
                
                if result.content:
                    for content in result.content:
                        if content.type == "text":
                            try:
                                data = json.loads(content.text)
                                campaigns = data.get('campaigns', [])
                                print(f"✅ Found {len(campaigns)} active campaigns")
                                for idx, campaign in enumerate(campaigns[:3]):
                                    print(f"   {idx+1}. {campaign.get('name')} (ID: {campaign.get('campaignId')})")
                            except:
                                print(f"Response: {content.text[:200]}...")
                else:
                    print("❌ No content in response")
                    
            except Exception as e:
                print(f"❌ Error: {e}")
            
            print("\n" + "=" * 60)
            print("✅ Dynamic server API test completed!")


if __name__ == "__main__":
    asyncio.run(test_api_calls())