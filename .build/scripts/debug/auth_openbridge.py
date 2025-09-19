#!/usr/bin/env python3
"""Authorization helper for Amazon Ads API using Openbridge redirect URLs.

This script generates the authorization URL for you to manually complete the OAuth flow.
"""

import urllib.parse
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


def generate_auth_url():
    """Generate the Amazon Ads API authorization URL."""
    client_id = os.getenv("AMAZON_ADS_CLIENT_ID")
    
    if not client_id:
        print("❌ Missing AMAZON_ADS_CLIENT_ID in .env file")
        return
    
    # Amazon Ads OAuth2 authorization URL
    auth_base_url = "https://www.amazon.com/ap/oa"
    
    # Use one of the allowed redirect URIs
    redirect_uri = "https://oauth.api.openbridge.io/oauth/callback"
    
    # Build authorization URL with advertising scope
    params = {
        "client_id": client_id,
        "scope": "advertising::campaign_management",
        "response_type": "code",
        "redirect_uri": redirect_uri,
    }
    
    auth_url = f"{auth_base_url}?{urllib.parse.urlencode(params)}"
    
    print("🔐 Amazon Ads API Authorization")
    print("=" * 50)
    print("\n1. Visit this URL in your browser:")
    print(f"\n{auth_url}\n")
    print("\n2. Log in with your Amazon account and grant access")
    print("\n3. After authorization, you'll be redirected to Openbridge")
    print("   Copy the 'code' parameter from the redirect URL")
    print("\n4. Use the code with the exchange_code.py script to get your refresh token")
    print("\nExample redirect URL:")
    print("https://oauth.api.openbridge.io/oauth/callback?code=YOUR_AUTH_CODE_HERE")


if __name__ == "__main__":
    generate_auth_url()