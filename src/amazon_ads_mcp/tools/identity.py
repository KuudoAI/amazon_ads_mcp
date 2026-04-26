"""MCP tools for identity management.

This module provides MCP tools for managing remote identities
for Amazon Ads API access, including listing, selecting, and
querying identity information.

The tools provide:

- List all available remote identities from OpenBridge
- Set active identity for Amazon Ads API operations
- Get current active identity information
- Get detailed information about specific identities
- Comprehensive error handling and logging

Examples:
    >>> identities = await list_remote_identities()
    >>> active = await get_active_identity()
    >>> response = await set_active_identity(
    ...     SetActiveIdentityRequest(identity_id="123")
    ... )
"""

import logging
from typing import Optional

from ..auth.manager import get_auth_manager
from ..models import (
    Identity,
    IdentityListResponse,
    SetActiveIdentityRequest,
    SetActiveIdentityResponse,
)

logger = logging.getLogger(__name__)


async def list_remote_identities(
    identity_type: Optional[str] = "14",
) -> IdentityListResponse:
    """List all available Amazon Ads remote identities.

    Returns a list of remote identities that can be used to access
    different Amazon Ads accounts through OpenBridge. By default, filters
    for Amazon Ads identities (type 14). The function handles both
    OpenBridge and direct authentication providers.

    The function automatically determines the provider type and calls the
    appropriate method for listing identities. For OpenBridge providers,
    it passes the identity_type filter to get only relevant identities.

    :param identity_type: Filter by remote identity type (default "14" for Amazon Ads)
    :type identity_type: Optional[str]
    :return: Response containing the list of available identities
    :rtype: IdentityListResponse
    :raises Exception: If listing identities fails

    .. note::
       Identity type "14" corresponds to Amazon Ads identities in OpenBridge.

    .. example::
       >>> response = await list_remote_identities()
       >>> print(f"Found {response.total} identities")
    """
    logger.info(f"Listing remote identities (type={identity_type})")

    try:
        auth_manager = get_auth_manager()
        # Pass the identity_type filter to the provider
        if hasattr(auth_manager.provider, "list_identities"):
            identities = await auth_manager.provider.list_identities(
                identity_type=identity_type
            )
        else:
            identities = await auth_manager.list_identities()

        return IdentityListResponse(
            identities=identities, total=len(identities), has_more=False
        )
    except Exception as e:
        logger.error(f"Failed to list identities: {e}")
        raise


async def get_active_identity() -> Optional[Identity]:
    """Get the currently active remote identity.

    Returns the identity that is currently being used for Amazon Ads API calls.
    This function provides access to the currently selected identity
    and logs information about it for debugging purposes.

    The function retrieves the active identity from the authentication manager
    and logs relevant information for troubleshooting.

    :return: The active Identity, or None if no identity is set
    :rtype: Optional[Identity]

    .. example::
       >>> identity = await get_active_identity()
       >>> if identity:
       ...     print(f"Active: {identity.attributes.get('name')}")
    """
    logger.info("Getting active identity")

    auth_manager = get_auth_manager()
    active_identity = auth_manager.get_active_identity()

    if active_identity:
        name = active_identity.attributes.get("name", active_identity.id)
        logger.info(f"Active identity: {name} ({active_identity.id})")
    else:
        logger.info("No active identity set")

    return active_identity


async def set_active_identity(
    request: SetActiveIdentityRequest,
) -> SetActiveIdentityResponse:
    """Set the active remote identity for Amazon Ads API operations.

    This identity will be used for all subsequent Amazon Ads API calls
    until a different identity is selected. The function also attempts
    to pre-load credentials for the selected identity.

    The function performs identity validation and credential pre-loading
    to ensure the selected identity is ready for use. If credential
    loading fails, the identity is still set but a warning is included
    in the response.

    :param request: Request containing the identity_id to activate
    :type request: SetActiveIdentityRequest
    :return: Response indicating success and the activated identity
    :rtype: SetActiveIdentityResponse
    :raises ValueError: If the specified identity is invalid
    :raises Exception: If setting the active identity fails

    .. example::
       >>> request = SetActiveIdentityRequest(identity_id="abc123")
       >>> response = await set_active_identity(request)
       >>> if response.success:
       ...     print("Identity activated successfully")
    """
    logger.info(f"Setting active identity: {request.identity_id}")

    try:
        auth_manager = get_auth_manager()

        # Set the active identity
        identity = await auth_manager.set_active_identity(request.identity_id)

        # Try to pre-load credentials
        credentials_loaded = False
        message = None
        try:
            await auth_manager.get_active_credentials()
            credentials_loaded = True
            logger.info("Credentials pre-loaded successfully")
        except Exception as e:
            message = f"Identity set but credentials not loaded: {str(e)}"
            logger.warning(message)

        return SetActiveIdentityResponse(
            success=True,
            identity=identity,
            credentials_loaded=credentials_loaded,
            message=message,
        )

    except ValueError as e:
        # auth_manager.set_active_identity raises ValueError("Identity X not
        # found") for bad IDs. Re-raise as typed ValidationError so the
        # envelope translator classifies as mcp_input_validation, not the
        # default internal_error bucket.
        from ..utils.errors import ValidationError

        logger.error(f"Invalid identity: {e}")
        err = ValidationError(str(e), field="identity_id")
        err.details["error_code"] = "IDENTITY_NOT_FOUND"
        raise err from e
    except Exception as e:
        logger.error(f"Failed to set active identity: {e}")
        raise


async def get_identity_info(identity_id: str) -> Optional[Identity]:
    """Get detailed information about a specific remote identity.

    Retrieves detailed information about a specific remote identity
    by its unique identifier. This function is useful for getting
    additional details about an identity before selecting it.

    The function queries the authentication manager for the specified
    identity and returns its details including attributes and metadata.

    :param identity_id: The ID of the identity to retrieve
    :type identity_id: str
    :return: The Identity if found, None otherwise
    :rtype: Optional[Identity]
    :raises Exception: If retrieving identity info fails

    .. example::
       >>> identity = await get_identity_info("abc123")
       >>> if identity:
       ...     name = identity.attributes.get("name", "Unknown")
       ...     print(f"Identity: {name}")
    """
    logger.info(f"Getting identity info for: {identity_id}")

    try:
        auth_manager = get_auth_manager()
        identity = await auth_manager.get_identity(identity_id)

        if identity:
            name = identity.attributes.get("name", identity.id)
            logger.info(f"Found identity: {name}")
        else:
            logger.info(f"Identity not found: {identity_id}")

        return identity
    except Exception as e:
        logger.error(f"Failed to get identity info: {e}")
        raise


async def list_identities() -> IdentityListResponse:
    """List all available identities.

    Retrieves a list of all available identities from the current
    authentication provider. This is a simplified wrapper around
    list_remote_identities for common use cases.

    This function uses the default identity type filter and is equivalent
    to calling list_remote_identities() with no parameters.

    :return: List of available identities
    :rtype: IdentityListResponse
    :raises Exception: If listing identities fails

    .. example::
       >>> identities = await list_identities()
       >>> for identity in identities.identities:
       ...     print(f"ID: {identity.id}")
    """
    return await list_remote_identities()
