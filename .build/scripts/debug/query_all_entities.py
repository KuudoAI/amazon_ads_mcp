#!/usr/bin/env python3
"""Query all entities for profile ID 1043817530956285."""

import asyncio
import json
import sys
from pathlib import Path
from datetime import datetime

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

import httpx
from amazon_ads_mcp.auth.openbridge_auth import OpenbridgeAuth
from amazon_ads_mcp.config.settings import settings


async def query_entities():
    """Query all entity types for the profile."""
    print("🔍 Querying All Entities for Profile 1043817530956285")
    print("=" * 50)
    
    profile_id = "1043817530956285"
    
    # Get authentication
    print("\n1. Getting authentication...")
    openbridge_auth = OpenbridgeAuth(refresh_token=settings.openbridge_refresh_token)
    token_info = await openbridge_auth.get_amazon_ads_token(settings.openbridge_remote_identity_id)
    print(f"   ✅ Got token")
    
    # Base headers
    headers = {
        "Authorization": f"Bearer {token_info['access_token']}",
        "Amazon-Advertising-API-ClientId": token_info['client_id'],
        "Amazon-Advertising-API-Scope": str(profile_id),
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    
    # Query configurations for each entity type - API only accepts one ad product at a time
    queries = [
        {
            "name": "Campaigns (SP)",
            "endpoint": "/adsApi/v1/query/campaigns",
            "body": {
                "adProductFilter": {
                    "include": ["SPONSORED_PRODUCTS"]
                },
                "stateFilter": {
                    "include": ["ENABLED", "PAUSED"]
                },
                "maxResults": 10
            }
        },
        {
            "name": "Campaigns (SB)",
            "endpoint": "/adsApi/v1/query/campaigns",
            "body": {
                "adProductFilter": {
                    "include": ["SPONSORED_BRANDS"]
                },
                "stateFilter": {
                    "include": ["ENABLED", "PAUSED"]
                },
                "maxResults": 5
            }
        },
        {
            "name": "Ad Groups (SP)",
            "endpoint": "/adsApi/v1/query/adGroups",
            "body": {
                "adProductFilter": {
                    "include": ["SPONSORED_PRODUCTS"]
                },
                "stateFilter": {
                    "include": ["ENABLED", "PAUSED"]
                },
                "maxResults": 10
            }
        },
        {
            "name": "Ads (SP)",
            "endpoint": "/adsApi/v1/query/ads",
            "body": {
                "adProductFilter": {
                    "include": ["SPONSORED_PRODUCTS"]
                },
                "stateFilter": {
                    "include": ["ENABLED", "PAUSED"]
                },
                "maxResults": 10
            }
        },
        {
            "name": "Targets (SP)",
            "endpoint": "/adsApi/v1/query/targets",
            "body": {
                "adProductFilter": {
                    "include": ["SPONSORED_PRODUCTS"]
                },
                "stateFilter": {
                    "include": ["ENABLED", "PAUSED"]
                },
                "maxResults": 10
            }
        }
    ]
    
    results = {}
    
    async with httpx.AsyncClient(timeout=60.0) as client:
        for query in queries:
            print(f"\n2. Querying {query['name']}...")
            
            try:
                response = await client.post(
                    f"{settings.region_endpoint}{query['endpoint']}",
                    headers=headers,
                    json=query['body']
                )
                
                print(f"   Status: {response.status_code}")
                
                if response.status_code == 200:
                    data = response.json()
                    
                    # Extract the entity list based on endpoint
                    entity_key = query['endpoint'].split('/')[-1]  # e.g., "campaigns"
                    entities = data.get(entity_key, [])
                    
                    print(f"   ✅ Found {len(entities)} {query['name'].lower()}")
                    
                    # Show sample data
                    if entities:
                        print(f"\n   Sample {query['name']}:")
                        for i, entity in enumerate(entities[:3]):  # Show first 3
                            if query['name'] == "Campaigns":
                                print(f"   {i+1}. {entity.get('name', 'N/A')} (ID: {entity.get('campaignId')})")
                                print(f"      State: {entity.get('state')}")
                                print(f"      Ad Product: {entity.get('adProduct')}")
                                print(f"      Budget: ${entity.get('budget', {}).get('budget', 'N/A')}")
                            elif query['name'] == "Ad Groups":
                                print(f"   {i+1}. {entity.get('name', 'N/A')} (ID: {entity.get('adGroupId')})")
                                print(f"      State: {entity.get('state')}")
                                print(f"      Campaign ID: {entity.get('campaignId')}")
                            elif query['name'] == "Ads":
                                print(f"   {i+1}. {entity.get('name', 'N/A')} (ID: {entity.get('adId')})")
                                print(f"      State: {entity.get('state')}")
                                print(f"      Ad Group ID: {entity.get('adGroupId')}")
                            elif query['name'] == "Targets":
                                print(f"   {i+1}. Type: {entity.get('targetingType', 'N/A')} (ID: {entity.get('targetId')})")
                                print(f"      State: {entity.get('state')}")
                                print(f"      Expression: {entity.get('expression', [])}")
                    
                    # Check if there are more results
                    next_token = data.get('nextToken')
                    if next_token:
                        print(f"\n   ℹ️  More results available (nextToken provided)")
                    
                    results[query['name']] = {
                        "count": len(entities),
                        "has_more": bool(next_token),
                        "sample": entities[:3] if entities else []
                    }
                    
                else:
                    print(f"   ❌ Error: {response.text[:200]}...")
                    results[query['name']] = {
                        "error": f"{response.status_code}: {response.text[:100]}"
                    }
                    
            except Exception as e:
                print(f"   ❌ Exception: {e}")
                results[query['name']] = {"error": str(e)}
    
    # Save results summary
    summary_path = Path("data/query_results_summary.json")
    summary_path.parent.mkdir(exist_ok=True)
    
    with open(summary_path, 'w') as f:
        json.dump({
            "profile_id": profile_id,
            "timestamp": datetime.now().isoformat(),
            "results": results
        }, f, indent=2)
    
    print("\n" + "=" * 50)
    print("📊 Query Summary")
    print("=" * 50)
    
    total_entities = 0
    for entity_type, result in results.items():
        if "count" in result:
            count = result["count"]
            total_entities += count
            more = " (more available)" if result["has_more"] else ""
            print(f"{entity_type}: {count} entities{more}")
        else:
            print(f"{entity_type}: Error - {result.get('error', 'Unknown')}")
    
    print(f"\nTotal entities queried: {total_entities}")
    print(f"Results saved to: {summary_path}")
    
    await openbridge_auth.close()


if __name__ == "__main__":
    asyncio.run(query_entities())