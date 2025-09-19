#!/usr/bin/env python3
"""Export all data types from Amazon Ads API for a specific profile."""

import asyncio
import json
import sys
import gzip
import shutil
from pathlib import Path
from datetime import datetime

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

import httpx
from amazon_ads_mcp.auth.openbridge_auth import OpenbridgeAuth
from amazon_ads_mcp.config.settings import settings


async def wait_for_export(client: httpx.AsyncClient, export_id: str, headers: dict, export_type: str) -> dict:
    """Wait for export to complete and return the result."""
    max_attempts = 30  # Max 5 minutes
    attempt = 0
    
    while attempt < max_attempts:
        response = await client.get(
            f"{settings.region_endpoint}/exports/{export_id}",
            headers={
                **headers,
                "Accept": f"application/vnd.{export_type}export.v1+json",
            }
        )
        
        if response.status_code == 200:
            data = response.json()
            status = data['status']
            
            if status == 'COMPLETED':
                return data
            elif status == 'FAILED':
                raise Exception(f"Export failed: {data.get('error')}")
            
            # Still processing
            print(f"      Status: {status} (attempt {attempt + 1}/{max_attempts})")
            await asyncio.sleep(10)  # Wait 10 seconds
            attempt += 1
        else:
            raise Exception(f"Failed to get export status: {response.status_code} - {response.text}")
    
    raise Exception("Export timed out after 5 minutes")


async def download_export(url: str, filename: str):
    """Download export file from S3."""
    async with httpx.AsyncClient() as client:
        response = await client.get(url, follow_redirects=True)
        if response.status_code == 200:
            # Save compressed file
            gz_path = Path(f"data/exports/{filename}.gz")
            with open(gz_path, 'wb') as f:
                f.write(response.content)
            
            # Decompress and save JSON
            json_path = Path(f"data/exports/{filename}")
            with gzip.open(gz_path, 'rb') as f_in:
                with open(json_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            
            # Remove compressed file
            gz_path.unlink()
            
            return json_path
        else:
            raise Exception(f"Failed to download export: {response.status_code}")


async def export_all_data():
    """Export all data types for profile 1043817530956285."""
    print("📊 Exporting All Amazon Ads Data")
    print("=" * 50)
    
    profile_id = "1043817530956285"
    print(f"\nUsing Profile ID: {profile_id}")
    
    # Get authentication
    print("\n1. Getting authentication...")
    openbridge_auth = OpenbridgeAuth(refresh_token=settings.openbridge_refresh_token)
    token_info = await openbridge_auth.get_amazon_ads_token(settings.openbridge_remote_identity_id)
    print(f"   ✅ Got token")
    
    # Base headers
    base_headers = {
        "Authorization": f"Bearer {token_info['access_token']}",
        "Amazon-Advertising-API-ClientId": token_info['client_id'],
        "Amazon-Advertising-API-Scope": str(profile_id),
    }
    
    # Export configurations
    exports = [
        {
            "name": "campaigns",
            "endpoint": "/campaigns/export",
            "content_type": "application/vnd.campaignsexport.v1+json",
            "data": {
                "stateFilter": ["ENABLED", "PAUSED", "ARCHIVED"],
                "adProductFilter": ["SPONSORED_PRODUCTS", "SPONSORED_BRANDS", "SPONSORED_DISPLAY"]
            }
        },
        {
            "name": "ads",
            "endpoint": "/ads/export",
            "content_type": "application/vnd.adsexport.v1+json",
            "data": {
                "stateFilter": ["ENABLED", "PAUSED", "ARCHIVED"],
                "adProductFilter": ["SPONSORED_PRODUCTS", "SPONSORED_BRANDS", "SPONSORED_DISPLAY"]
            }
        },
        {
            "name": "adGroups",
            "endpoint": "/adGroups/export",
            "content_type": "application/vnd.adgroupsexport.v1+json",
            "data": {
                "stateFilter": ["ENABLED", "PAUSED", "ARCHIVED"],
                "adProductFilter": ["SPONSORED_PRODUCTS", "SPONSORED_BRANDS", "SPONSORED_DISPLAY"]
            }
        },
        {
            "name": "targets",
            "endpoint": "/targets/export",
            "content_type": "application/vnd.targetsexport.v1+json",
            "data": {
                "stateFilter": ["ENABLED", "PAUSED", "ARCHIVED"],
                "adProductFilter": ["SPONSORED_PRODUCTS", "SPONSORED_BRANDS", "SPONSORED_DISPLAY"],
                "targetTypeFilter": ["AUTO", "KEYWORD", "PRODUCT_CATEGORY", "PRODUCT", "PRODUCT_CATEGORY_AUDIENCE", "PRODUCT_AUDIENCE", "AUDIENCE", "THEME"],
                "targetLevelFilter": ["CAMPAIGN", "AD_GROUP"],
                "negativeFilter": [True, False]
            }
        }
    ]
    
    # Track results
    results = []
    
    async with httpx.AsyncClient(timeout=60.0) as client:
        for export_config in exports:
            print(f"\n2. Creating {export_config['name']} export...")
            
            try:
                # Create export
                headers = {
                    **base_headers,
                    "Content-Type": export_config['content_type'],
                    "Accept": export_config['content_type'],
                }
                
                response = await client.post(
                    f"{settings.region_endpoint}{export_config['endpoint']}",
                    headers=headers,
                    json=export_config['data']
                )
                
                if response.status_code == 202:
                    export_data = response.json()
                    export_id = export_data['exportId']
                    print(f"   ✅ Export created: {export_id}")
                    
                    # Wait for completion
                    print("   ⏳ Waiting for export to complete...")
                    completed_data = await wait_for_export(client, export_id, base_headers, export_config['name'])
                    
                    # Download file
                    print(f"   📥 Downloading export file...")
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    filename = f"{export_config['name']}_{profile_id}_{timestamp}.json"
                    
                    file_path = await download_export(completed_data['url'], filename)
                    
                    # Load and show summary
                    with open(file_path, 'r') as f:
                        exported_data = json.load(f)
                    
                    record_count = len(exported_data) if isinstance(exported_data, list) else 1
                    
                    print(f"   ✅ Export complete!")
                    print(f"      Records: {record_count}")
                    print(f"      File: {file_path}")
                    print(f"      Size: {completed_data.get('fileSize', 0):,} bytes")
                    
                    results.append({
                        "type": export_config['name'],
                        "export_id": export_id,
                        "status": "SUCCESS",
                        "records": record_count,
                        "file": str(file_path),
                        "file_size": completed_data.get('fileSize', 0)
                    })
                    
                else:
                    print(f"   ❌ Failed to create export: {response.status_code}")
                    print(f"      Response: {response.text}")
                    results.append({
                        "type": export_config['name'],
                        "status": "FAILED",
                        "error": f"{response.status_code}: {response.text}"
                    })
                    
            except Exception as e:
                print(f"   ❌ Error: {e}")
                results.append({
                    "type": export_config['name'],
                    "status": "ERROR",
                    "error": str(e)
                })
    
    # Save summary
    summary_path = Path("data/exports/export_summary.json")
    with open(summary_path, 'w') as f:
        json.dump({
            "profile_id": profile_id,
            "timestamp": datetime.now().isoformat(),
            "exports": results
        }, f, indent=2)
    
    print("\n" + "=" * 50)
    print("📊 Export Summary")
    print("=" * 50)
    
    for result in results:
        print(f"\n{result['type'].upper()}:")
        print(f"  Status: {result['status']}")
        if result['status'] == "SUCCESS":
            print(f"  Records: {result['records']}")
            print(f"  File: {result['file']}")
            print(f"  Size: {result['file_size']:,} bytes")
        else:
            print(f"  Error: {result.get('error', 'Unknown')}")
    
    print(f"\nSummary saved to: {summary_path}")
    
    await openbridge_auth.close()


if __name__ == "__main__":
    asyncio.run(export_all_data())