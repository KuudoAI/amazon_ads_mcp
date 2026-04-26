"""Profile management tools for Amazon Ads MCP.

This module provides tools for managing Amazon Ads profiles,
including setting and getting the active profile ID.

The tools handle profile selection for API operations and
provide fallback mechanisms to default profiles when needed.

Key Features:

- Set active profile ID for API scope headers (validated against cached list)
- Retrieve current active profile with source information
- Clear profile settings to fall back to defaults
- Comprehensive error handling and logging

Examples:
    >>> result = await set_active_profile("123456789")
    >>> profile_info = await get_active_profile()
    >>> clear_result = await clear_active_profile()
"""

import logging
from difflib import get_close_matches

from ..auth.manager import get_auth_manager
from ..utils.errors import ValidationError

logger = logging.getLogger(__name__)


async def set_active_profile(profile_id: str) -> dict:
    """Set the active Amazon Ads profile ID.

    Validates the profile ID against the cached profile list before setting,
    raising :class:`ValidationError` for empty / whitespace / not-found IDs.
    This prevents silent acceptance of garbage strings that would otherwise
    surface as opaque 401s from Amazon downstream.

    Sets the profile ID to be used in the Amazon-Advertising-API-Scope
    header for subsequent API calls. This profile ID is associated with
    the current active identity and overrides any default profile.

    The profile ID will be used for all API requests until cleared or
    changed. This setting is per-identity and does not affect other
    active identities.

    :param profile_id: The Amazon Ads profile ID to use
    :type profile_id: str
    :return: Success response with profile ID confirmation
    :rtype: dict
    :raises ValidationError: If ``profile_id`` is empty/whitespace, or not
        present in the cached profile list. The error includes a
        ``did_you_mean`` hint when a close-match exists in the cache.
    :raises Exception: If setting the active profile fails for other reasons.

    .. example::
       >>> result = await set_active_profile("123456789")
       >>> print(f"Profile set: {result['profile_id']}")
    """
    # Reject empty / non-string up front
    if not isinstance(profile_id, str) or not profile_id.strip():
        err = ValidationError(
            "profile_id must be a non-empty string",
            field="profile_id",
        )
        # Attach error_code post-init: ValidationError.__init__ has a
        # known issue with the ``details`` kwarg (would collide in super().__init__).
        err.details["error_code"] = "INVALID_PROFILE_ID"
        raise err

    # Validate against the cached profile list
    # Lazy import: avoids a circular dependency at module-load time
    from .profile_listing import get_profiles_cached

    profiles, _stale = await get_profiles_cached()
    valid_ids = {str(p.get("profileId")) for p in profiles if p.get("profileId") is not None}

    if profile_id not in valid_ids:
        suggestions = get_close_matches(profile_id, list(valid_ids), n=3, cutoff=0.5)
        err = ValidationError(
            f"Profile {profile_id!r} not found in cached profile list. "
            f"Use page_profiles or search_profiles to discover valid IDs.",
            field="profile_id",
        )
        err.details["error_code"] = "PROFILE_NOT_FOUND"
        if suggestions:
            err.details["hints"] = [
                {"kind": "did_you_mean", "suggestions": suggestions}
            ]
        raise err

    # Happy path — preserve SetProfileResponse shape (success, profile_id, message)
    try:
        auth_manager = get_auth_manager()
        auth_manager.set_active_profile_id(profile_id)

        return {
            "success": True,
            "profile_id": profile_id,
            "message": f"Active profile set to {profile_id}",
        }
    except Exception as e:
        logger.error(f"Failed to set active profile: {e}")
        raise


async def get_active_profile() -> dict:
    """Get the currently active Amazon Ads profile ID.

    Returns the profile ID that will be used for API requests,
    which could be from:

    1. Explicitly set profile for current identity
    2. Default from AMAZON_ADS_PROFILE_ID environment variable
    3. None if no profile is set

    The response includes information about the source of the
    profile ID for debugging purposes.

    The function provides transparency about where the profile ID
    originates from to help with troubleshooting API scope issues.

    :return: Current profile information with source details
    :rtype: dict
    :raises Exception: If getting the active profile fails

    .. example::
       >>> profile_info = await get_active_profile()
       >>> print(f"Profile: {profile_info.get('profile_id')}")
       >>> print(f"Source: {profile_info.get('source')}")
    """
    try:
        auth_manager = get_auth_manager()
        profile_id = auth_manager.get_active_profile_id()

        if profile_id:
            return {
                "success": True,
                "profile_id": profile_id,
                "source": auth_manager.get_profile_source(),
            }
        else:
            return {
                "success": True,
                "profile_id": None,
                "message": "No active profile set",
            }
    except Exception as e:
        logger.error(f"Failed to get active profile: {e}")
        raise


async def clear_active_profile() -> dict:
    """Clear the active profile ID for the current identity.

    Removes the explicitly set profile ID, falling back to the
    default profile ID from environment if available. This is
    useful for resetting profile selection to system defaults.

    After clearing, the profile selection falls back to the
    AMAZON_ADS_PROFILE_ID environment variable if set, or None
    if no default is configured.

    :return: Success response with fallback profile information
    :rtype: dict
    :raises Exception: If clearing the active profile fails

    .. example::
       >>> result = await clear_active_profile()
       >>> if result.get('fallback_profile_id'):
       ...     print(f"Fell back to: {result['fallback_profile_id']}")
    """
    try:
        auth_manager = get_auth_manager()
        auth_manager.clear_active_profile_id()

        # Check what we're falling back to
        fallback_profile = auth_manager.get_active_profile_id()

        if fallback_profile:
            return {
                "success": True,
                "message": "Profile cleared",
                "fallback_profile_id": fallback_profile,
            }
        else:
            return {
                "success": True,
                "message": "Profile cleared, no fallback profile available",
            }
    except Exception as e:
        logger.error(f"Failed to clear active profile: {e}")
        raise
