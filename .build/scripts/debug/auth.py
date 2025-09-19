#!/usr/bin/env python3
"""Authorization flow for Amazon Ads API.

This script helps you get the refresh token needed for the Amazon Ads API.
Run this script to start the OAuth2 authorization flow.
"""

import asyncio
import json
import urllib.parse
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
from typing import Optional, Dict

import httpx
from dotenv import load_dotenv, set_key
import os

# Load environment variables
load_dotenv()


class AuthorizationHandler(BaseHTTPRequestHandler):
    """Handler for OAuth2 callback."""
    
    authorization_code: Optional[str] = None
    error: Optional[str] = None
    
    def log_message(self, format, *args):
        """Suppress default logging."""
        pass
    
    def do_GET(self):
        """Handle GET request from OAuth callback."""
        # Parse query parameters
        parsed_path = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed_path.query)
        
        # Extract authorization code or error
        if 'code' in params:
            AuthorizationHandler.authorization_code = params['code'][0]
            response_body = b"""
            <html>
            <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
                <h1 style="color: #4CAF50;">✅ Authorization Successful!</h1>
                <p>You can close this window and return to the terminal.</p>
            </body>
            </html>
            """
        elif 'error' in params:
            AuthorizationHandler.error = params.get('error', ['Unknown error'])[0]
            response_body = b"""
            <html>
            <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
                <h1 style="color: #f44336;">❌ Authorization Failed</h1>
                <p>Please check the terminal for more information.</p>
            </body>
            </html>
            """
        else:
            response_body = b"Invalid response"
        
        # Send response
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(response_body)


async def get_authorization_code(client_id: str, redirect_uri: str = "https://oauth.api.openbridge.io/oauth/callback") -> Optional[str]:
    """Start OAuth2 flow to get authorization code."""
    # Amazon Ads OAuth2 authorization URL
    auth_base_url = "https://www.amazon.com/ap/oa"
    
    # Build authorization URL
    params = {
        "client_id": client_id,
        "scope": "advertising::campaign_management",
        "response_type": "code",
        "redirect_uri": redirect_uri,
    }
    
    auth_url = f"{auth_base_url}?{urllib.parse.urlencode(params)}"
    
    print("\n🌐 Opening browser for authorization...")
    print(f"\nIf the browser doesn't open automatically, visit this URL:")
    print(f"\n{auth_url}\n")
    
    # Start local server for callback
    server = HTTPServer(('localhost', 8888), AuthorizationHandler)
    server_thread = Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    
    # Open browser
    webbrowser.open(auth_url)
    
    # Wait for authorization
    print("⏳ Waiting for authorization...")
    print("   Please log in with your Amazon account and grant access.")
    
    # Poll for authorization code
    for _ in range(120):  # Wait up to 2 minutes
        await asyncio.sleep(1)
        if AuthorizationHandler.authorization_code:
            server.shutdown()
            return AuthorizationHandler.authorization_code
        elif AuthorizationHandler.error:
            server.shutdown()
            print(f"\n❌ Authorization error: {AuthorizationHandler.error}")
            return None
    
    server.shutdown()
    print("\n❌ Authorization timeout")
    return None


async def exchange_code_for_tokens(client_id: str, client_secret: str, authorization_code: str, 
                                  redirect_uri: str = "https://oauth.api.openbridge.io/oauth/callback") -> Optional[Dict[str, str]]:
    """Exchange authorization code for access and refresh tokens."""
    token_url = "https://api.amazon.com/auth/o2/token"
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                token_url,
                data={
                    "grant_type": "authorization_code",
                    "code": authorization_code,
                    "redirect_uri": redirect_uri,
                    "client_id": client_id,
                    "client_secret": client_secret,
                },
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            )
            response.raise_for_status()
            return response.json()
            
        except httpx.HTTPStatusError as e:
            print(f"❌ Failed to exchange code: {e.response.status_code}")
            print(f"   Response: {e.response.text}")
            return None
        except Exception as e:
            print(f"❌ Error exchanging code: {e}")
            return None


async def refresh_access_token(client_id: str, client_secret: str, refresh_token: str) -> Optional[Dict[str, str]]:
    """Get a new access token using refresh token."""
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
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            )
            response.raise_for_status()
            return response.json()
            
        except httpx.HTTPStatusError as e:
            print(f"❌ Failed to refresh token: {e.response.status_code}")
            print(f"   Response: {e.response.text}")
            return None
        except Exception as e:
            print(f"❌ Error refreshing token: {e}")
            return None


async def main():
    """Main authorization flow."""
    print("🔐 Amazon Ads API Authorization Setup")
    print("=" * 50)
    
    # Get credentials
    client_id = os.getenv("AMAZON_ADS_CLIENT_ID")
    client_secret = os.getenv("AMAZON_ADS_CLIENT_SECRET")
    existing_refresh_token = os.getenv("AMAZON_ADS_REFRESH_TOKEN")
    
    if not client_id or not client_secret:
        print("❌ Missing credentials. Please set in .env file:")
        print("   - AMAZON_ADS_CLIENT_ID")
        print("   - AMAZON_ADS_CLIENT_SECRET")
        return
    
    print("✅ Found client credentials")
    
    # Check if we already have a refresh token
    if existing_refresh_token:
        print("\n📌 Existing refresh token found")
        choice = input("\nDo you want to:\n1. Test existing token\n2. Get new token\n\nChoice (1 or 2): ")
        
        if choice == "1":
            print("\n🔄 Testing refresh token...")
            token_data = await refresh_access_token(client_id, client_secret, existing_refresh_token)
            if token_data:
                print("✅ Refresh token is valid!")
                print(f"   Access token obtained (expires in {token_data.get('expires_in', 0)} seconds)")
            else:
                print("❌ Refresh token is invalid. Please run auth flow again.")
            return
    
    # Start OAuth2 flow
    print("\n🚀 Starting OAuth2 authorization flow...")
    
    # Step 1: Get authorization code
    auth_code = await get_authorization_code(client_id)
    if not auth_code:
        print("❌ Failed to get authorization code")
        return
    
    print(f"\n✅ Got authorization code: {auth_code[:10]}...")
    
    # Step 2: Exchange for tokens
    print("\n🔄 Exchanging code for tokens...")
    token_data = await exchange_code_for_tokens(client_id, client_secret, auth_code)
    
    if not token_data:
        print("❌ Failed to get tokens")
        return
    
    print("✅ Successfully obtained tokens!")
    
    # Save refresh token to .env
    refresh_token = token_data.get("refresh_token")
    if refresh_token:
        env_file = ".env"
        set_key(env_file, "AMAZON_ADS_REFRESH_TOKEN", refresh_token)
        print(f"\n💾 Refresh token saved to {env_file}")
        print("   You can now run the MCP server!")
    
    # Display token info
    print("\n📋 Token Information:")
    print(f"   Access Token: {token_data.get('access_token', '')[:20]}...")
    print(f"   Expires In: {token_data.get('expires_in', 0)} seconds")
    print(f"   Token Type: {token_data.get('token_type', 'N/A')}")
    
    print("\n✅ Setup complete! You can now run the MCP server.")


if __name__ == "__main__":
    asyncio.run(main())