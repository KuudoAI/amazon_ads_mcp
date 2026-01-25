"""Response models for builtin MCP tools.

This module defines structured Pydantic response models for all builtin tools
in the Amazon Ads MCP server. These models enable:
- Client-side validation of tool responses
- IDE autocompletion and type hints
- Automatic JSON schema generation for MCP clients
- Self-documenting API responses

All models inherit from BaseModel with consistent patterns:
- `success: bool` field for operation status
- Optional `message: str` for human-readable feedback
- Typed fields for all response data
"""

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


# ============================================================================
# Region Tool Responses
# ============================================================================


class RegionInfo(BaseModel):
    """Information about a single Amazon Ads region.

    :param name: Human-readable region name
    :param api_endpoint: API endpoint URL for this region
    :param oauth_endpoint: OAuth token endpoint URL
    :param marketplaces: List of marketplace codes in this region
    :param sandbox: Whether this is a sandbox endpoint
    """

    name: str
    api_endpoint: str
    oauth_endpoint: str
    marketplaces: List[str]
    sandbox: bool = False


class SetRegionResponse(BaseModel):
    """Response from set_region tool.

    :param success: Whether the operation succeeded
    :param previous_region: Region before the change
    :param new_region: Region after the change
    :param region_name: Human-readable name of new region
    :param api_endpoint: API endpoint URL for new region
    :param oauth_endpoint: OAuth endpoint URL (if available)
    :param message: Human-readable status message
    :param error: Error code if operation failed
    :param identity: Identity name if region is identity-controlled
    """

    success: bool
    previous_region: Optional[str] = None
    new_region: Optional[str] = None
    region_name: Optional[str] = None
    api_endpoint: Optional[str] = None
    oauth_endpoint: Optional[str] = None
    message: Optional[str] = None
    error: Optional[str] = None
    identity: Optional[str] = None
    current_identity: Optional[str] = None
    identity_region: Optional[str] = None
    requested_region: Optional[str] = None
    region: Optional[str] = None


class GetRegionResponse(BaseModel):
    """Response from get_region tool.

    :param success: Whether the operation succeeded
    :param region: Current region code (na/eu/fe)
    :param region_name: Human-readable region name
    :param api_endpoint: API endpoint URL
    :param oauth_endpoint: OAuth endpoint URL (if using direct auth)
    :param sandbox_mode: Whether sandbox mode is enabled
    :param auth_method: Authentication method (direct/openbridge)
    :param source: Where region setting comes from (identity/config)
    :param identity_region: Region from active identity (if applicable)
    """

    success: bool
    region: str
    region_name: str
    api_endpoint: str
    oauth_endpoint: Optional[str] = None
    sandbox_mode: bool = False
    auth_method: Literal["direct", "openbridge"] = "openbridge"
    source: Literal["identity", "config"] = "config"
    identity_region: Optional[str] = None


class ListRegionsResponse(BaseModel):
    """Response from list_regions tool.

    :param success: Whether the operation succeeded
    :param current_region: Currently active region code
    :param sandbox_mode: Whether sandbox mode is enabled
    :param regions: Map of region code to region info
    """

    success: bool
    current_region: str
    sandbox_mode: bool = False
    regions: Dict[str, RegionInfo]


# ============================================================================
# Profile Tool Responses
# ============================================================================


class SetProfileResponse(BaseModel):
    """Response from set_active_profile tool.

    :param success: Whether the operation succeeded
    :param profile_id: The profile ID that was set
    :param message: Human-readable status message
    """

    success: bool
    profile_id: str
    message: str


class GetProfileResponse(BaseModel):
    """Response from get_active_profile tool.

    :param success: Whether the operation succeeded
    :param profile_id: Current active profile ID (None if not set)
    :param source: Where profile setting comes from (explicit/environment/default)
    :param message: Human-readable status message (when no profile set)
    """

    success: bool
    profile_id: Optional[str] = None
    source: Optional[str] = None
    message: Optional[str] = None


class ClearProfileResponse(BaseModel):
    """Response from clear_active_profile tool.

    :param success: Whether the operation succeeded
    :param message: Human-readable status message
    :param fallback_profile_id: Profile ID that will be used after clearing
    """

    success: bool
    message: str
    fallback_profile_id: Optional[str] = None


# ============================================================================
# Identity Tool Responses
# ============================================================================


class GetActiveIdentityResponse(BaseModel):
    """Response from get_active_identity tool.

    :param success: Whether the operation succeeded
    :param identity: Active identity details (None if not set)
    :param message: Human-readable status message
    """

    success: bool
    identity: Optional[Dict[str, Any]] = None
    message: Optional[str] = None


class ProfileSelectorResponse(BaseModel):
    """Response from select_profile interactive tool.

    :param success: Whether the operation succeeded
    :param action: User action (accept/decline/cancel)
    :param profile_id: Selected profile ID (if accepted)
    :param profile_name: Selected profile name/description (if accepted)
    :param message: Human-readable status message
    """

    success: bool
    action: Literal["accept", "decline", "cancel"]
    profile_id: Optional[str] = None
    profile_name: Optional[str] = None
    message: str


# ============================================================================
# Profile Listing Tool Responses
# ============================================================================


class ProfileListItem(BaseModel):
    """Normalized profile list item used by wrapper tools.

    :param profile_id: Amazon Ads profile ID
    :param name: Account name or advertiser name
    :param country_code: Marketplace country code
    :param type: Account type (seller/vendor/agency)
    """

    profile_id: str
    name: str
    country_code: str
    type: str


class ProfileSummaryResponse(BaseModel):
    """Response from summarize_profiles tool.

    :param total_count: Total profiles available
    :param by_country: Counts by country code
    :param by_type: Counts by account type
    :param message: Optional guidance or status message
    :param stale: Whether cached data was used after a refresh failure
    """

    total_count: int
    by_country: Dict[str, int]
    by_type: Dict[str, int]
    message: Optional[str] = None
    stale: bool = False


class ProfileSearchResponse(BaseModel):
    """Response from search_profiles tool.

    :param items: Matching profile items
    :param total_count: Total matches available
    :param returned_count: Number of items returned
    :param has_more: Whether more matches are available
    :param message: Optional guidance or status message
    :param stale: Whether cached data was used after a refresh failure
    """

    items: List[ProfileListItem]
    total_count: int
    returned_count: int
    has_more: bool
    message: Optional[str] = None
    stale: bool = False


class ProfilePageResponse(BaseModel):
    """Response from page_profiles tool.

    :param items: Page of profile items
    :param total_count: Total profiles available for this filter
    :param returned_count: Number of items returned
    :param has_more: Whether more items are available
    :param next_offset: Offset for the next page (if available)
    :param message: Optional guidance or status message
    :param stale: Whether cached data was used after a refresh failure
    """

    items: List[ProfileListItem]
    total_count: int
    returned_count: int
    has_more: bool
    next_offset: Optional[int] = None
    message: Optional[str] = None
    stale: bool = False


class ProfileCacheRefreshResponse(BaseModel):
    """Response from refresh_profiles_cache tool.

    :param success: Whether the refresh succeeded
    :param total_count: Total profiles cached
    :param cache_timestamp: Timestamp of the cached data (epoch seconds)
    :param stale: Whether cached data was returned after refresh failure
    :param message: Optional guidance or status message
    """

    success: bool
    total_count: int
    cache_timestamp: Optional[float] = None
    stale: bool = False
    message: Optional[str] = None


# ============================================================================
# Download Tool Responses
# ============================================================================


class DownloadExportResponse(BaseModel):
    """Response from download_export tool.

    :param success: Whether the download succeeded
    :param file_path: Local path where file was saved
    :param export_type: Type of export (campaigns/adgroups/ads/targets/general)
    :param message: Human-readable status message
    """

    success: bool
    file_path: str
    export_type: str
    message: str


class DownloadedFile(BaseModel):
    """Information about a downloaded file.

    :param filename: Name of the file
    :param path: Full path to the file
    :param size: File size in bytes
    :param modified: Last modified timestamp
    :param resource_type: Type of resource (report/export/etc)
    """

    filename: str
    path: str
    size: int
    modified: str
    resource_type: Optional[str] = None


class ListDownloadsResponse(BaseModel):
    """Response from list_downloads tool.

    :param success: Whether the operation succeeded
    :param files: List of downloaded files
    :param count: Total number of files
    :param download_dir: Directory where downloads are stored
    """

    success: bool
    files: List[DownloadedFile]
    count: int
    download_dir: str


# ============================================================================
# Reporting Tool Responses
# ============================================================================


class AsyncReportResponse(BaseModel):
    """Response from request_async_report tool.

    :param success: Whether the report was generated successfully
    :param report_id: Amazon Ads report ID
    :param report_type: Type of report requested
    :param file_path: Local path where report was saved (if successful)
    :param status: Final report status
    :param error: Error message if operation failed
    :param download_url: Report download URL (if available but download failed)
    :param message: Human-readable status message
    """

    success: bool
    report_id: Optional[str] = None
    report_type: Optional[str] = None
    file_path: Optional[str] = None
    status: Optional[str] = None
    error: Optional[str] = None
    download_url: Optional[str] = None
    message: Optional[str] = None


# ============================================================================
# OAuth Tool Responses
# ============================================================================


class OAuthFlowResponse(BaseModel):
    """Response from start_oauth_flow tool.

    :param success: Whether the flow started successfully
    :param authorization_url: URL to redirect user for authorization
    :param state: OAuth state parameter for CSRF protection
    :param message: Human-readable status message
    """

    success: bool
    authorization_url: Optional[str] = None
    state: Optional[str] = None
    message: Optional[str] = None


class OAuthStatusResponse(BaseModel):
    """Response from check_oauth_status tool.

    :param success: Whether the check succeeded
    :param authenticated: Whether user is authenticated
    :param token_valid: Whether current token is valid
    :param expires_at: Token expiration timestamp
    :param scopes: Granted OAuth scopes
    :param message: Human-readable status message
    """

    success: bool
    authenticated: bool = False
    token_valid: bool = False
    expires_at: Optional[str] = None
    scopes: Optional[List[str]] = None
    message: Optional[str] = None


class OAuthRefreshResponse(BaseModel):
    """Response from refresh_oauth_token tool.

    :param success: Whether the refresh succeeded
    :param message: Human-readable status message
    :param expires_at: New token expiration timestamp
    """

    success: bool
    message: str
    expires_at: Optional[str] = None


class OAuthClearResponse(BaseModel):
    """Response from clear_oauth_tokens tool.

    :param success: Whether the clear succeeded
    :param message: Human-readable status message
    """

    success: bool
    message: str


# ============================================================================
# Routing State Response
# ============================================================================


class RoutingStateResponse(BaseModel):
    """Response from get_routing_state tool.

    :param region: Current region code
    :param host: API host URL
    :param headers: Current routing headers
    :param sandbox: Whether sandbox mode is enabled
    """

    region: str
    host: str
    headers: Dict[str, str] = Field(default_factory=dict)
    sandbox: bool = False


# ============================================================================
# Sampling Tool Responses
# ============================================================================


class SamplingTestResponse(BaseModel):
    """Response from test_sampling tool.

    :param success: Whether sampling executed successfully
    :param message: Human-readable status message
    :param response: Response from the sampled model
    :param sampling_enabled: Whether sampling is enabled in settings
    :param used_fallback: Note about fallback usage
    :param error: Error message if operation failed
    :param note: Additional notes about configuration
    """

    success: bool
    message: Optional[str] = None
    response: Optional[str] = None
    sampling_enabled: bool = False
    used_fallback: Optional[str] = None
    error: Optional[str] = None
    note: Optional[str] = None
