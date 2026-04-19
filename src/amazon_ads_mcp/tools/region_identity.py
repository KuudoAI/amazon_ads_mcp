"""Region-aware identity selection tools.

This module provides tools to help find and switch to identities
in specific regions when using OpenBridge authentication.
"""

import logging
from typing import Dict, Optional

from ..auth.manager import get_auth_manager

logger = logging.getLogger(__name__)


async def list_identities_by_region(region: Optional[str] = None) -> Dict:
    """List identities grouped by region.

    This is particularly useful for OpenBridge authentication where
    regions are tied to identities rather than being freely switchable.

    :param region: Optional region filter ('na', 'eu', 'fe')
    :type region: Optional[str]
    :return: Dictionary with identities grouped by region
    :rtype: Dict
    """
    try:
        auth_manager = get_auth_manager()

        # Get all identities
        if hasattr(auth_manager.provider, "list_identities"):
            all_identities = await auth_manager.provider.list_identities()
        else:
            all_identities = await auth_manager.list_identities()

        # Group by region
        by_region = {"na": [], "eu": [], "fe": [], "unknown": []}

        for identity in all_identities:
            identity_region = identity.attributes.get("region", "unknown").lower()
            if identity_region in by_region:
                by_region[identity_region].append(
                    {
                        "id": identity.id,
                        "name": identity.attributes.get("name", identity.id),
                        "email": identity.attributes.get("email", ""),
                        "region": identity_region,
                        "account_id": identity.attributes.get("account_id", ""),
                    }
                )
            else:
                by_region["unknown"].append(
                    {
                        "id": identity.id,
                        "name": identity.attributes.get("name", identity.id),
                        "region": identity_region,
                    }
                )

        # Get current active identity
        current_identity = auth_manager.get_active_identity()
        current_id = current_identity.id if current_identity else None

        # Filter by region if specified
        if region and region in ["na", "eu", "fe"]:
            filtered = {
                region: by_region[region],
                "total": len(by_region[region]),
                "current_identity": current_id,
                "message": f"Found {len(by_region[region])} identities in {region.upper()} region",
            }
            return filtered

        # Return all grouped by region
        return {
            "regions": by_region,
            "totals": {k: len(v) for k, v in by_region.items()},
            "current_identity": current_id,
            "message": "Identities grouped by region",
        }

    except Exception as e:
        logger.error(f"Failed to list identities by region: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "Failed to list identities by region",
        }


async def switch_to_region_identity(
    target_region: str, identity_id: Optional[str] = None
) -> Dict:
    """Switch to an identity in the specified region.

    If identity_id is provided, switches to that specific identity if it's in the
    target region. Otherwise, switches to the first available identity in the region.

    :param target_region: Target region ('na', 'eu', 'fe')
    :type target_region: str
    :param identity_id: Optional specific identity ID to switch to
    :type identity_id: Optional[str]
    :return: Result of the switch operation
    :rtype: Dict
    """
    try:
        if target_region not in ["na", "eu", "fe"]:
            return {
                "success": False,
                "error": "INVALID_REGION",
                "message": f"Invalid region: {target_region}. Must be 'na', 'eu', or 'fe'",
            }

        # Get identities in the target region
        region_data = await list_identities_by_region(target_region)

        if "error" in region_data:
            return region_data

        target_identities = region_data.get(target_region, [])

        if not target_identities:
            return {
                "success": False,
                "error": "NO_IDENTITIES",
                "message": f"No identities found in {target_region.upper()} region",
                "region": target_region,
            }

        # If specific identity requested, validate it's in the region
        if identity_id:
            matching = [i for i in target_identities if i["id"] == identity_id]
            if not matching:
                return {
                    "success": False,
                    "error": "IDENTITY_NOT_IN_REGION",
                    "message": f"Identity {identity_id} is not in {target_region.upper()} region",
                    "available_identities": target_identities,
                }
            selected = matching[0]
        else:
            # Select first available identity in region
            selected = target_identities[0]

        # Switch to the selected identity
        from ..models import SetActiveIdentityRequest

        request = SetActiveIdentityRequest(identity_id=selected["id"])

        from . import identity

        result = await identity.set_active_identity(request)

        if result.success:
            return {
                "success": True,
                "message": f"Switched to {selected['name']} in {target_region.upper()} region",
                "identity": selected,
                "region": target_region,
                "credentials_loaded": result.credentials_loaded,
            }
        else:
            return {
                "success": False,
                "error": "SWITCH_FAILED",
                "message": f"Failed to switch to identity: {result.message}",
                "identity": selected,
            }

    except Exception as e:
        logger.error(f"Failed to switch to region identity: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "Failed to switch to region identity",
        }
