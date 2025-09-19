#!/usr/bin/env python3
"""Get just the access token for manual testing."""

import asyncio
from dotenv import load_dotenv
from amazon_ads_mcp.config.settings import settings
from amazon_ads_mcp.utils.auth import AmazonAdsAuth

load_dotenv()


async def get_token():
    auth = AmazonAdsAuth(
        client_id=settings.amazon_ads_client_id,
        client_secret=settings.amazon_ads_client_secret,
        refresh_token=settings.amazon_ads_refresh_token,
    )
    
    await auth.get_access_token()
    print(auth.access_token)


if __name__ == "__main__":
    asyncio.run(get_token())