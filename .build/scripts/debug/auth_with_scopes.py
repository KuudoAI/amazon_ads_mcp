#!/usr/bin/env python3
"""Authorization helper with different scope options for Amazon Ads API."""

import urllib.parse
import os
import sys
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Available scopes for Amazon Ads API
SCOPES = {
    "1": "profile",  # Basic profile access
    "2": "profile postal_code",  # Profile with postal code
    "3": "profile:user_id",  # Profile with user ID
    "4": "cpc_advertising:campaign_management",  # Campaign management (if available)
}


def generate_auth_url(scope_choice="1"):
    """Generate the Amazon Ads API authorization URL."""
    client_id = os.getenv("AMAZON_ADS_CLIENT_ID")
    
    if not client_id:
        print("❌ Missing AMAZON_ADS_CLIENT_ID in .env file")
        return
    
    # Amazon Ads OAuth2 authorization URL
    auth_base_url = "https://www.amazon.com/ap/oa"
    
    # Use one of the allowed redirect URIs
    redirect_uri = "https://oauth.api.openbridge.io/oauth/callback"
    
    # Get selected scope
    selected_scope = SCOPES.get(scope_choice, SCOPES["1"])
    
    # Build authorization URL
    params = {
        "client_id": client_id,
        "scope": selected_scope,
        "response_type": "code",
        "redirect_uri": redirect_uri,
    }
    
    auth_url = f"{auth_base_url}?{urllib.parse.urlencode(params)}"
    
    print("🔐 Amazon Ads API Authorization")
    print("=" * 50)
    print(f"\nUsing scope: {selected_scope}")
    print("\n1. Visit this URL in your browser:")
    print(f"\n{auth_url}\n")
    print("\n2. Log in with your Amazon account and grant access")
    print("\n3. After authorization, you'll be redirected to Openbridge")
    print("   Copy the 'code' parameter from the redirect URL")
    print("\n4. Use the code with the exchange_code.py script to get your refresh token")


if __name__ == "__main__":
    print("Select scope option:")
    for key, scope in SCOPES.items():
        print(f"  {key}: {scope}")
    
    choice = input("\nEnter choice (default: 1): ").strip() or "1"
    
    if choice in SCOPES:
        generate_auth_url(choice)
    else:
        print("Invalid choice, using default scope")
        generate_auth_url("1")