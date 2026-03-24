"""Manage Amazon Ads API region for the MCP server.

Provide utilities to set, inspect, and list region information including
endpoints and sandbox state.

Examples
--------
.. code-block:: python

   import asyncio
   from amazon_ads_mcp.tools.region import set_active_region, get_active_region

   async def main():
       await set_active_region("na")
       info = await get_active_region()
       print(info["region"])  # "na"

   asyncio.run(main())
"""

import logging
from ..auth.manager import get_auth_manager
from ..config.settings import Settings

logger = logging.getLogger(__name__)


async def set_active_region(region: str) -> dict:
    """Set the active Amazon Ads API region.

    Update API and OAuth endpoints for subsequent calls. When the provider
    binds region to identity, advise switching identities instead.

    :param region: Target region ("na", "eu", or "fe").
    :return: Result payload with region info and endpoints.
    :raises ValueError: If the region value is invalid.
    :raises Exception: If updating the region fails.
    """
    try:
        # Normalize to lowercase so callers can pass "NA", "EU", etc.
        region = region.strip().lower()

        # Validate region
        if region not in ["na", "eu", "fe"]:
            raise ValueError(f"Invalid region: {region}. Must be 'na', 'eu', or 'fe'")

        # Get auth manager to check provider capabilities
        auth_manager = get_auth_manager()

        # Check if provider controls region through identity
        if (
            hasattr(auth_manager.provider, "region_controlled_by_identity")
            and auth_manager.provider.region_controlled_by_identity()
        ):
            # For providers where region is identity-controlled, we can't directly set the region
            # The region is determined by the active identity
            current_identity = auth_manager.get_active_identity()
            if current_identity:
                identity_region = current_identity.attributes.get("region", "na")
                if identity_region != region:
                    return {
                        "success": False,
                        "error": "REGION_MISMATCH",
                        "message": f"Cannot set region to '{region}' when using {auth_manager.provider.provider_type} authentication. "
                        f"Current identity is in '{identity_region}' region. "
                        f"Please select an identity in the '{region}' region instead.",
                        "current_identity": current_identity.attributes.get(
                            "name", current_identity.id
                        ),
                        "identity_region": identity_region,
                        "requested_region": region,
                    }
                else:
                    # Region already matches the identity's region
                    return {
                        "success": True,
                        "message": f"Region is already set to '{region}' via OpenBridge identity",
                        "region": region,
                        "identity": current_identity.attributes.get(
                            "name", current_identity.id
                        ),
                    }
            else:
                return {
                    "success": False,
                    "error": "NO_IDENTITY",
                    "message": "No active identity set. Please select an identity first using 'set_active_identity'",
                    "requested_region": region,
                }

        # For non-OpenBridge providers (like DirectAmazonAdsProvider)
        # Get the current region first
        old_region = (
            auth_manager.provider.region
            if hasattr(auth_manager.provider, "region")
            else "na"
        )

        # If using direct auth, update the provider's region
        if hasattr(auth_manager.provider, "_region"):
            # For DirectAmazonAdsProvider - it has a settable _region attribute
            auth_manager.provider._region = region
            # Note: OAuth endpoint is determined dynamically via get_oauth_endpoint()
            # so no need to update it explicitly

            # Clear cached tokens as they might be region-specific
            if hasattr(auth_manager.provider, "_access_token"):
                auth_manager.provider._access_token = None
                logger.info("Cleared cached access token due to region change")

        # Map region to name for clarity
        region_names = {
            "na": "North America",
            "eu": "Europe",
            "fe": "Far East",
        }

        # Get the new endpoint URLs from provider if available
        if hasattr(auth_manager.provider, "get_region_endpoint"):
            region_endpoint = auth_manager.provider.get_region_endpoint(region)
        else:
            # Fallback to settings for display
            settings = Settings()
            region_endpoint = settings.region_endpoint

        # Get OAuth endpoint if available
        oauth_endpoint = None
        if hasattr(auth_manager.provider, "get_oauth_endpoint"):
            oauth_endpoint = auth_manager.provider.get_oauth_endpoint(region)

        # Build response
        response = {
            "success": True,
            "previous_region": old_region,
            "new_region": region,
            "region_name": region_names[region],
            "api_endpoint": region_endpoint,
            "message": f"Region changed from {old_region} to {region}",
        }

        # Add OAuth endpoint if available
        if oauth_endpoint:
            response["oauth_endpoint"] = oauth_endpoint

        logger.info(
            f"Region changed from {old_region} to {region} ({region_names[region]})"
        )
        return response

    except Exception as e:
        logger.error(f"Failed to set active region: {e}")
        raise


async def get_active_region() -> dict:
    """Return information about the active region.

    Include endpoints, sandbox mode, active auth method, and whether the
    region source is identity or configuration.

    :return: Region information with endpoints and metadata.
    :raises Exception: If retrieval fails.
    """
    try:
        # Get auth manager to access current region
        auth_manager = get_auth_manager()

        # Get region from provider if available, otherwise use default
        if hasattr(auth_manager.provider, "region"):
            region = auth_manager.provider.region
        else:
            # Fallback to environment/default if provider doesn't have region
            settings = Settings()
            region = settings.amazon_ads_region

        # Map region to name
        region_names = {
            "na": "North America",
            "eu": "Europe",
            "fe": "Far East",
        }

        # Get endpoint URLs from provider if available, otherwise from settings
        if hasattr(auth_manager.provider, "get_region_endpoint"):
            region_endpoint = auth_manager.provider.get_region_endpoint()
        else:
            settings = Settings()
            region_endpoint = settings.region_endpoint

        # Get sandbox mode from settings
        settings = Settings()
        sandbox_mode = settings.amazon_ads_sandbox_mode

        response = {
            "success": True,
            "region": region,
            "region_name": region_names.get(region, "Unknown"),
            "api_endpoint": region_endpoint,
            "sandbox_mode": sandbox_mode,
        }

        # Add OAuth endpoint if available
        if hasattr(auth_manager.provider, "get_oauth_endpoint"):
            response["oauth_endpoint"] = auth_manager.provider.get_oauth_endpoint()
            response["auth_method"] = "direct"
        else:
            response["auth_method"] = "openbridge"

        # Check if region is from identity (OpenBridge) or config
        if auth_manager.get_active_identity():
            identity_region = auth_manager.get_active_region()
            if identity_region:
                response["identity_region"] = identity_region
                response["source"] = (
                    "identity" if identity_region == region else "config"
                )
            else:
                response["source"] = "config"
        else:
            response["source"] = "config"

        return response

    except Exception as e:
        logger.error(f"Failed to get active region: {e}")
        raise


async def list_available_regions() -> dict:
    """List available regions and their endpoints.

    Include API and OAuth endpoints, marketplaces, sandbox mode, and the
    currently selected region.

    :return: Mapping containing region details.
    :raises Exception: If listing fails.
    """
    try:
        # Get auth manager to access current region
        auth_manager = get_auth_manager()

        # Get current region from provider or settings
        if hasattr(auth_manager.provider, "region"):
            current_region = auth_manager.provider.region
        else:
            settings = Settings()
            current_region = settings.amazon_ads_region

        # Get sandbox mode from settings
        settings = Settings()
        sandbox_mode = settings.amazon_ads_sandbox_mode

        regions = {
            "na": {
                "name": "North America",
                "api_endpoint": "https://advertising-api.amazon.com",
                "oauth_endpoint": "https://api.amazon.com/auth/o2/token",
                "marketplaces": ["US", "CA", "MX", "BR"],
            },
            "eu": {
                "name": "Europe",
                "api_endpoint": "https://advertising-api-eu.amazon.com",
                "oauth_endpoint": "https://api.amazon.co.uk/auth/o2/token",
                "marketplaces": [
                    "UK",
                    "DE",
                    "FR",
                    "IT",
                    "ES",
                    "NL",
                    "AE",
                    "SE",
                    "PL",
                    "TR",
                    "SG",
                    "AU",
                    "IN",
                ],
            },
            "fe": {
                "name": "Far East",
                "api_endpoint": "https://advertising-api-fe.amazon.com",
                "oauth_endpoint": "https://api.amazon.co.jp/auth/o2/token",
                "marketplaces": ["JP"],
            },
        }

        # Adjust for sandbox mode
        if sandbox_mode:
            for region_data in regions.values():
                region_data["api_endpoint"] = region_data["api_endpoint"].replace(
                    "advertising-api", "advertising-api-test"
                )
                region_data["sandbox"] = True

        return {
            "success": True,
            "current_region": current_region,
            "sandbox_mode": sandbox_mode,
            "regions": regions,
        }

    except Exception as e:
        logger.error(f"Failed to list regions: {e}")
        raise


# Alias functions for backward compatibility with builtin_tools
async def set_region(region: str) -> dict:
    """Alias for set_active_region for backward compatibility."""
    return await set_active_region(region)


async def get_region() -> dict:
    """Alias for get_active_region for backward compatibility."""
    return await get_active_region()


async def list_regions() -> dict:
    """Alias for list_available_regions for backward compatibility."""
    return await list_available_regions()
