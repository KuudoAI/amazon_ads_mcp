#!/usr/bin/env python3
"""Test Amazon Ads API authentication flow directly."""

import asyncio
import httpx
import json


async def test_auth():
    """Test the authentication flow."""
    print("🔐 Testing Amazon Ads API Authentication")
    print("=" * 50)
    
    # From Openbridge
    access_token = "Atza|IwEBIChsbEmh6iMFVMMVBGCq2TusZWSt3eGi6-CzVjtGNsmOXHTRtlA68IAytnQQ-rkhZvZeayeYd7eFw6SwRCCl_pnItZUeJwzjCxwvWYpxbuWsminC4q0s_RNlKTUYwJfY6I4oGJSfyIMCoMYBWNRhUMYwmRpafQVEtfOKxZREScoUoer893DQPpPZXwMLyUPT94QXFUxlKk_Jdupjat_ODYzLVSHQ1DbBezEqbU1TzPOletzQQwaYrjtoDIUbFIY6ZAu95xSsPt-sLrYs0HCLoLOqTatCJCu__CW2hmQTmn8q55CYBTwCf2QvygpPkIHU_OP_eTwPg0K9UpESuUPuykxs"
    client_id = "amzn1.application-oa2-client.5571543b64ac404fafb8ff468c898443"
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        # Test different endpoints
        endpoints = [
            ("User Info", "https://api.amazon.com/user/profile"),
            ("Profiles", "https://advertising-api.amazon.com/v2/profiles"),
            ("Test Accounts", "https://advertising-api.amazon.com/testAccounts"),
            ("Account Info", "https://advertising-api.amazon.com/v2/accounts"),
        ]
        
        for name, url in endpoints:
            print(f"\n📍 Testing {name}: {url}")
            
            # Try with different header combinations
            header_combos = [
                {
                    "Authorization": f"Bearer {access_token}",
                    "Amazon-Advertising-API-ClientId": client_id,
                    "Content-Type": "application/json",
                },
                {
                    "Authorization": f"Bearer {access_token}",
                    "Amazon-Advertising-API-ClientId": client_id,
                    "Content-Type": "application/json",
                    "Amazon-Advertising-API-Scope": "profile",
                },
                {
                    "Authorization": f"Bearer {access_token}",
                    "x-amz-access-token": access_token,
                    "Amazon-Advertising-API-ClientId": client_id,
                    "Content-Type": "application/json",
                },
            ]
            
            for i, headers in enumerate(header_combos):
                try:
                    response = await client.get(url, headers=headers)
                    print(f"   Attempt {i+1}: Status {response.status_code}")
                    
                    if response.status_code != 401:
                        print(f"   Headers used: {list(headers.keys())}")
                        print(f"   Response: {response.text[:200]}...")
                        if response.status_code == 200:
                            print("   ✅ SUCCESS!")
                            break
                except Exception as e:
                    print(f"   Error: {e}")
            
            # If we found a working endpoint, stop
            if response.status_code == 200:
                break


if __name__ == "__main__":
    asyncio.run(test_auth())