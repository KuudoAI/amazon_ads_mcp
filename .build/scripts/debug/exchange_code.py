#!/usr/bin/env python3
"""Exchange authorization code for refresh token."""

import asyncio
import os
import sys
import httpx
from dotenv import load_dotenv, set_key

# Load environment variables
load_dotenv()


async def exchange_code(auth_code: str):
    """Exchange authorization code for tokens."""
    client_id = os.getenv("AMAZON_ADS_CLIENT_ID")
    client_secret = os.getenv("AMAZON_ADS_CLIENT_SECRET")
    
    if not client_id or not client_secret:
        print("❌ Missing credentials in .env file:")
        print("   - AMAZON_ADS_CLIENT_ID")
        print("   - AMAZON_ADS_CLIENT_SECRET")
        return
    
    token_url = "https://api.amazon.com/auth/o2/token"
    redirect_uri = "https://oauth.api.openbridge.io/oauth/callback"
    
    print("🔄 Exchanging authorization code for tokens...")
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                token_url,
                data={
                    "grant_type": "authorization_code",
                    "code": auth_code,
                    "redirect_uri": redirect_uri,
                    "client_id": client_id,
                    "client_secret": client_secret,
                },
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            )
            response.raise_for_status()
            token_data = response.json()
            
            print("✅ Successfully obtained tokens!")
            
            # Save refresh token to .env
            refresh_token = token_data.get("refresh_token")
            if refresh_token:
                set_key(".env", "AMAZON_ADS_REFRESH_TOKEN", refresh_token)
                print(f"\n💾 Refresh token saved to .env")
                
                # Display token info
                print("\n📋 Token Information:")
                print(f"   Access Token: {token_data.get('access_token', '')[:20]}...")
                print(f"   Expires In: {token_data.get('expires_in', 0)} seconds")
                print(f"   Token Type: {token_data.get('token_type', 'N/A')}")
                
                print("\n✅ Setup complete! You can now run the MCP server.")
            else:
                print("❌ No refresh token in response")
                print(f"Response: {token_data}")
                
        except httpx.HTTPStatusError as e:
            print(f"❌ Failed to exchange code: {e.response.status_code}")
            print(f"   Response: {e.response.text}")
        except Exception as e:
            print(f"❌ Error: {e}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python exchange_code.py <authorization_code>")
        print("\nExample:")
        print("  python exchange_code.py ANLQexampleCodeHere123")
        sys.exit(1)
    
    auth_code = sys.argv[1]
    asyncio.run(exchange_code(auth_code))