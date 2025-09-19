#!/usr/bin/env python3
"""Authorization helper with correct Amazon Ads API scope."""

import urllib.parse
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


def generate_auth_url():
    """Generate the Amazon Ads API authorization URL with correct scope."""
    client_id = os.getenv("AMAZON_ADS_CLIENT_ID")
    
    if not client_id:
        print("❌ Missing AMAZON_ADS_CLIENT_ID in .env file")
        return
    
    # Amazon Ads OAuth2 authorization URL
    auth_base_url = "https://www.amazon.com/ap/oa"
    
    # Use one of the allowed redirect URIs
    redirect_uri = "https://oauth.api.openbridge.io/oauth/callback"
    
    print("🔐 Amazon Ads API Authorization")
    print("=" * 50)
    print("\nIMPORTANT: Amazon Ads API Authorization")
    print("\nThe issue might be that the accounts you're using don't have")
    print("Amazon Advertising accounts set up, or the app isn't approved.")
    print("\nFor Amazon Ads API to work, you need:")
    print("1. An app registered at https://advertising.amazon.com/API/")
    print("2. The app must be approved for production access")
    print("3. The Amazon account must have an advertising account")
    print("4. The account must have created at least one campaign")
    
    # Try with standard profile scope first
    params = {
        "client_id": client_id,
        "scope": "profile",
        "response_type": "code",
        "redirect_uri": redirect_uri,
    }
    
    auth_url = f"{auth_base_url}?{urllib.parse.urlencode(params)}"
    
    print("\n\nAuthorization URL:")
    print(f"\n{auth_url}\n")
    
    print("\nNOTE: Even with valid tokens, you'll get 401 errors if:")
    print("- The app isn't approved for Amazon Ads API access")
    print("- The account doesn't have advertising profiles")
    print("- The app only has sandbox access, not production")


if __name__ == "__main__":
    generate_auth_url()