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

from typing import Annotated, Any, Dict, List, Literal, Optional, Tuple, Union

from pydantic import BaseModel, ConfigDict, Field


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
    :param session_present: Whether the call ran inside an MCP session
        that keeps auth state across subsequent tool calls. ``None``
        when not computed.
    :param state_scope: ``"session"`` when state will persist across
        the next tool call, ``"request"`` when the caller must
        re-establish context every call. ``None`` when not computed.
    :param state_reason: Diagnostic explaining ``state_scope`` or
        flagging that prior state was wiped. Known values:
        ``"no_mcp_session"``, ``"token_swapped"``, ``"bridge_unavailable"``.
    """

    success: bool
    profile_id: Optional[str] = None
    source: Optional[str] = None
    message: Optional[str] = None
    session_present: Optional[bool] = None
    state_scope: Optional[str] = None
    state_reason: Optional[str] = None


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
    :param session_present: Whether the call ran inside an MCP session
        that keeps auth state across subsequent tool calls. ``None``
        when not computed.
    :param state_scope: ``"session"`` when state will persist across
        the next tool call, ``"request"`` when the caller must
        re-establish context every call. ``None`` when not computed.
    :param state_reason: Diagnostic explaining ``state_scope`` or
        flagging that prior state was wiped. Known values:
        ``"no_mcp_session"``, ``"token_swapped"``, ``"bridge_unavailable"``.

    Note on shape: prior versions of the ``get_active_identity`` tool
    returned the bare ``Identity`` object. The tool now wraps it in
    this response model so the three state fields can travel
    alongside it. Existing callers that read ``identity.id`` directly
    must read ``response["identity"]["id"]`` instead.
    """

    success: bool
    identity: Optional[Dict[str, Any]] = None
    message: Optional[str] = None
    session_present: Optional[bool] = None
    state_scope: Optional[str] = None
    state_reason: Optional[str] = None


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


class GetDownloadUrlResponse(BaseModel):
    """Response from get_download_url tool.

    :param success: Whether the URL was generated successfully
    :param download_url: HTTP URL to download the file
    :param file_name: Name of the file
    :param size_bytes: File size in bytes
    :param profile_id: Profile ID the file belongs to
    :param instructions: Instructions for using the download URL
    :param error: Error message if failed
    :param hint: Helpful hint for resolving issues
    """

    success: bool
    download_url: Optional[str] = None
    file_name: Optional[str] = None
    size_bytes: Optional[int] = None
    profile_id: Optional[str] = None
    instructions: Optional[str] = None
    error: Optional[str] = None
    hint: Optional[str] = None


class ReadDownloadResponse(BaseModel):
    """Response from read_download tool."""

    success: bool
    file_path: Optional[str] = None
    profile_id: Optional[str] = None
    offset: int = 0
    bytes_read: int = 0
    size_bytes: Optional[int] = None
    truncated: bool = False
    encoding: Optional[str] = None
    content: Optional[str] = None
    content_base64: Optional[str] = None
    error: Optional[str] = None
    hint: Optional[str] = None


class SetContextResponse(BaseModel):
    """Response from ``set_context`` tool.

    The three state fields tell agent clients how to manage context
    persistence across tool calls:

    * ``session_present`` — pure transport fact: did this call run
      inside a long-lived MCP session?
    * ``state_scope`` — directive: ``"session"`` means the transport
      will keep auth state across the next tool call; ``"request"``
      means the caller must re-issue ``set_context`` every block.
    * ``state_reason`` — diagnostic explaining ``state_scope`` or
      flagging that prior state was wiped despite a session being
      present. Known values: ``"no_mcp_session"``, ``"token_swapped"``,
      ``"bridge_unavailable"``. ``None`` on the happy path.
    """

    success: bool
    identity_id: Optional[str] = None
    region: Optional[str] = None
    profile_id: Optional[str] = None
    message: Optional[str] = None
    error: Optional[str] = None
    session_present: Optional[bool] = None
    state_scope: Optional[str] = None
    state_reason: Optional[str] = None


class ListReportFieldsResponse(BaseModel):
    """Response from list_report_fields tool."""

    success: bool
    operation: Optional[str] = None
    operations: Optional[List[str]] = None
    catalog: Optional[Dict[str, Any]] = None
    catalog_entry: Optional[Dict[str, Any]] = None
    message: Optional[str] = None
    error: Optional[str] = None
    hint: Optional[str] = None


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


class GetSessionStateResponse(BaseModel):
    """Response from the dedicated ``get_session_state`` probe tool.

    The probe carries exactly the three state fields and nothing else.
    It is the documented entry point for an agent to learn the
    transport's session scope at the start of a block:

    * ``session_present`` — pure transport fact; ``True`` when the
      transport keeps a long-lived MCP session.
    * ``state_scope`` — caller directive: ``"session"`` means context
      survives across tool calls in this block; ``"request"`` means
      every call must re-establish context.
    * ``state_reason`` — diagnostic. ``None`` on the happy path. When
      non-null, takes one of:

        - ``"no_mcp_session"`` — transport has no long-lived MCP
          session (e.g. stateless HTTP). ``state_scope`` will be
          ``"request"``.
        - ``"token_swapped"`` — the transport DOES support sessions,
          but a different bearer/refresh token arrived mid-session
          and the previous tenant's identity, credentials, and
          profile were cleared. ``state_scope`` stays ``"session"``
          but the caller must re-establish context for the new
          tenant before the next call.
        - ``"bridge_unavailable"`` — reserved; the session bridge
          ran but could not persist state. Treat as ``"request"``.

    Decision rule for agents: re-establish context before the next
    tool call iff ``state_scope == "request"`` or ``state_reason is
    not null``.
    """

    session_present: bool
    state_scope: str
    state_reason: Optional[str] = None


class RoutingStateResponse(BaseModel):
    """Response from get_routing_state tool.

    :param region: Current region code
    :param host: API host URL
    :param headers: Current routing headers
    :param sandbox: Whether sandbox mode is enabled
    :param session_present: Whether the call ran inside an MCP session
        that keeps auth/region state across subsequent tool calls.
        ``None`` when not computed.
    :param state_scope: ``"session"`` when routing state will persist
        across the next tool call, ``"request"`` when the caller must
        re-establish region every call. ``None`` when not computed.
    :param state_reason: Diagnostic explaining ``state_scope``. Known
        values: ``"no_mcp_session"``, ``"token_swapped"``,
        ``"bridge_unavailable"``.
    """

    region: str
    host: str
    headers: Dict[str, str] = Field(default_factory=dict)
    sandbox: bool = False
    session_present: Optional[bool] = None
    state_scope: Optional[str] = None
    state_reason: Optional[str] = None


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


# ============================================================================
# Tool Group (Progressive Disclosure) Responses
# ============================================================================


class ToolGroupInfo(BaseModel):
    """Information about a single tool group.

    :param prefix: Tool name prefix (e.g., 'cm', 'dsp')
    :param tool_count: Number of tools in this group
    :param enabled: Whether the group is currently enabled
    """

    prefix: str
    tool_count: int
    enabled: bool


class ToolGroupsResponse(BaseModel):
    """Response from list_tool_groups tool.

    :param success: Whether the operation succeeded
    :param groups: Available tool groups
    :param total_tools: Total tool count across all groups
    :param enabled_tools: Number of currently enabled tools
    :param message: Human-readable summary
    """

    success: bool
    groups: List[ToolGroupInfo] = Field(default_factory=list)
    total_tools: int = 0
    enabled_tools: int = 0
    message: Optional[str] = None


class EnableToolGroupResponse(BaseModel):
    """Response from enable_tool_group tool.

    :param success: Whether the operation succeeded
    :param prefix: The group prefix that was enabled/disabled
    :param enabled: Whether the group is now enabled
    :param tool_count: Number of tools affected
    :param tool_names: Exact tool names available after enable
    :param message: Human-readable result
    :param error: Error message if operation failed
    """

    success: bool
    prefix: Optional[str] = None
    enabled: bool = False
    tool_count: int = 0
    tool_names: List[str] = Field(default_factory=list)
    message: Optional[str] = None
    error: Optional[str] = None


# ============================================================================
# report_fields Tool Responses (adsv1.md §4.5) — extra="forbid" scoped to these
# models only; existing models above intentionally preserve their permissive
# contracts.
# ============================================================================


class CatalogSourceMeta(BaseModel):
    """Provenance pointer for a single v1 catalog record.

    Returned only on detail lookups (`mode="query"`, `fields=[...]`).
    """

    model_config = ConfigDict(extra="forbid")

    md_file: str
    parsed_at: str  # ISO timestamp from the source parser


class ReportFieldEntry(BaseModel):
    """A single entry in the report_fields catalog query result."""

    model_config = ConfigDict(extra="forbid")

    field_id: str
    display_name: str
    data_type: str
    category: Literal["dimension", "metric", "filter", "time"]
    provenance: Literal["empirical", "documented", "schema-derived"]
    short_description: str  # always; clipped to <=160 chars upstream

    # Detail-only:
    description: Optional[str] = None

    # Always-applicable (may be empty; always included in output):
    required_fields: List[str] = Field(default_factory=list)
    complementary_fields: List[str] = Field(default_factory=list)

    # Compatibility graph — dropped via exclude_none when empty.
    # Source-side (populated on metric records by Amazon; carries display labels):
    compatible_dimensions: Optional[List[str]] = None
    incompatible_dimensions: Optional[List[str]] = None
    # Inverted index (built at refresh; attached to dimension records so the
    # graph is queryable from either direction):
    compatible_metrics: Optional[List[str]] = None
    incompatible_metrics: Optional[List[str]] = None

    # Optional cross-references — None when not requested or not applicable:
    v3_name_dsp: Optional[str] = None
    v3_name_sponsored_ads: Optional[str] = None

    source: Optional[CatalogSourceMeta] = None  # detail lookup only


class QueryReportFieldsResponse(BaseModel):
    """Response for `report_fields(mode="query", ...)`."""

    model_config = ConfigDict(extra="forbid")

    mode: Literal["query"]  # discriminator
    success: bool
    operation: str
    catalog_schema_version: int
    parsed_at: str  # ISO timestamp
    stale_warning: Optional[str] = None
    truncated: bool = False
    truncated_reason: Optional[Literal["byte_cap", "limit", "field_filter"]] = None
    total_matching: int
    returned: int
    offset: int
    limit: int
    fields: List[ReportFieldEntry] = Field(default_factory=list)


class ValidateReportFieldsResponse(BaseModel):
    """Response for `report_fields(mode="validate", ...)`."""

    model_config = ConfigDict(extra="forbid")

    mode: Literal["validate"]  # discriminator
    success: bool
    operation: str
    valid: bool
    unknown_fields: List[str] = Field(default_factory=list)
    missing_required: Dict[str, List[str]] = Field(default_factory=dict)
    incompatible_pairs: List[Tuple[str, str]] = Field(default_factory=list)
    suggested_replacements: Dict[str, List[str]] = Field(default_factory=dict)


#: Discriminated union tagged on the `mode` field.
ReportFieldsResponse = Annotated[
    Union[QueryReportFieldsResponse, ValidateReportFieldsResponse],
    Field(discriminator="mode"),
]


# ============================================================================
# Campaign Management Tool Responses
# ============================================================================


class UpdateCampaignResponse(BaseModel):
    """Response from update_sp_campaigns / update_sb_campaigns tools.

    :param success: Whether the update succeeded
    :param campaign_id: Campaign ID that was updated
    :param message: Human-readable status message
    :param updated_fields: Fields that were changed
    :param details: Raw API response details
    :param error: Error details if failed
    """

    success: bool
    campaign_id: str
    message: str
    updated_fields: Optional[Dict[str, Any]] = None
    details: Optional[Dict[str, Any]] = None
    error: Optional[Any] = None


class UpdateAdGroupResponse(BaseModel):
    """Response from update_sp_ad_groups tool.

    :param success: Whether the update succeeded
    :param ad_group_id: Ad group ID that was updated
    :param message: Human-readable status message
    :param updated_fields: Fields that were changed
    :param details: Raw API response details
    :param error: Error details if failed
    """

    success: bool
    ad_group_id: str
    message: str
    updated_fields: Optional[Dict[str, Any]] = None
    details: Optional[Dict[str, Any]] = None
    error: Optional[Any] = None


class UpdateKeywordResponse(BaseModel):
    """Response from update_sp_keywords tool.

    :param success: Whether the update succeeded
    :param keyword_id: Keyword ID that was updated
    :param message: Human-readable status message
    :param updated_fields: Fields that were changed
    :param details: Raw API response details
    :param error: Error details if failed
    """

    success: bool
    keyword_id: str
    message: str
    updated_fields: Optional[Dict[str, Any]] = None
    details: Optional[Dict[str, Any]] = None
    error: Optional[Any] = None


class UpdateProductAdResponse(BaseModel):
    """Response from update_sp_product_ads tool.

    :param success: Whether the update succeeded
    :param ad_id: Product ad ID that was updated
    :param message: Human-readable status message
    :param updated_fields: Fields that were changed
    :param details: Raw API response details
    :param error: Error details if failed
    """

    success: bool
    ad_id: str
    message: str
    updated_fields: Optional[Dict[str, Any]] = None
    details: Optional[Dict[str, Any]] = None
    error: Optional[Any] = None


class AdGroupItem(BaseModel):
    """Single ad group in a list response.

    :param ad_group_id: Ad group ID
    :param name: Ad group name
    :param campaign_id: Parent campaign ID
    :param state: Current state
    :param default_bid: Default bid amount
    """

    ad_group_id: Optional[str] = None
    name: Optional[str] = None
    campaign_id: Optional[str] = None
    state: Optional[str] = None
    default_bid: Optional[float] = None


class ListAdGroupsResponse(BaseModel):
    """Response from list_sp_ad_groups tool.

    :param success: Whether the request succeeded
    :param items: List of ad groups
    :param count: Number of items returned
    :param next_token: Pagination token for next page
    :param error: Error message if failed
    """

    success: bool
    items: List[AdGroupItem] = Field(default_factory=list)
    count: int = 0
    next_token: Optional[str] = None
    error: Optional[str] = None


class KeywordItem(BaseModel):
    """Single keyword in a list response.

    :param keyword_id: Keyword ID
    :param keyword_text: The keyword text
    :param match_type: Match type (BROAD, PHRASE, EXACT)
    :param campaign_id: Parent campaign ID
    :param ad_group_id: Parent ad group ID
    :param state: Current state
    :param bid: Current bid amount
    """

    keyword_id: Optional[str] = None
    keyword_text: Optional[str] = None
    match_type: Optional[str] = None
    campaign_id: Optional[str] = None
    ad_group_id: Optional[str] = None
    state: Optional[str] = None
    bid: Optional[float] = None


class ListKeywordsResponse(BaseModel):
    """Response from list_sp_keywords tool.

    :param success: Whether the request succeeded
    :param items: List of keywords
    :param count: Number of items returned
    :param next_token: Pagination token for next page
    :param error: Error message if failed
    """

    success: bool
    items: List[KeywordItem] = Field(default_factory=list)
    count: int = 0
    next_token: Optional[str] = None
    error: Optional[str] = None


class CreateCampaignResponse(BaseModel):
    success: bool
    campaign_id: Optional[str] = None
    message: str
    details: Optional[Dict[str, Any]] = None
    error: Optional[Any] = None


class CreateAdGroupResponse(BaseModel):
    success: bool
    ad_group_id: Optional[str] = None
    message: str
    details: Optional[Dict[str, Any]] = None
    error: Optional[Any] = None


class CreateKeywordResponse(BaseModel):
    success: bool
    keyword_id: Optional[str] = None
    message: str
    details: Optional[Dict[str, Any]] = None
    error: Optional[Any] = None


class CreateProductAdResponse(BaseModel):
    success: bool
    ad_id: Optional[str] = None
    message: str
    details: Optional[Dict[str, Any]] = None
    error: Optional[Any] = None


class CampaignItem(BaseModel):
    campaign_id: Optional[str] = None
    name: Optional[str] = None
    state: Optional[str] = None
    targeting_type: Optional[str] = None
    budget_amount: Optional[float] = None
    budget_type: Optional[str] = None
    portfolio_id: Optional[str] = None
    start_date: Optional[str] = None
    bidding_strategy: Optional[str] = None
    placement_top_pct: Optional[float] = 0
    placement_product_page_pct: Optional[float] = 0
    placement_rest_of_search_pct: Optional[float] = 0
    # Populated only when list_sp_campaigns is called with
    # include_extended_data=True. servingStatus is the delivery health
    # signal (e.g. CAMPAIGN_OUT_OF_BUDGET, CAMPAIGN_STATUS_ENABLED).
    serving_status: Optional[str] = None
    serving_status_details: Optional[List[Dict[str, Any]]] = None
    creation_date_time: Optional[str] = None
    last_update_date_time: Optional[str] = None
    # Full extendedData object as returned by the API. Lossless passthrough
    # so future fields Amazon adds aren't silently dropped — the flattened
    # convenience keys above are duplicated from this blob. None when
    # include_extended_data was not requested or the API returned no
    # extendedData on the campaign.
    extended_data: Optional[Dict[str, Any]] = None


class ListCampaignsResponse(BaseModel):
    success: bool
    items: List[CampaignItem] = Field(default_factory=list)
    count: int = 0
    next_token: Optional[str] = None
    error: Optional[str] = None


class ProductAdItem(BaseModel):
    ad_id: Optional[str] = None
    campaign_id: Optional[str] = None
    ad_group_id: Optional[str] = None
    asin: Optional[str] = None
    state: Optional[str] = None


class ListProductAdsResponse(BaseModel):
    success: bool
    items: List[ProductAdItem] = Field(default_factory=list)
    count: int = 0
    next_token: Optional[str] = None
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Portfolios
# ---------------------------------------------------------------------------

class PortfolioItem(BaseModel):
    portfolio_id: Optional[str] = None
    name: Optional[str] = None
    state: Optional[str] = None
    in_budget: Optional[bool] = None
    budget_policy: Optional[str] = None
    budget_currency: Optional[str] = None


class ListPortfoliosResponse(BaseModel):
    success: bool
    items: List[PortfolioItem] = Field(default_factory=list)
    count: int = 0
    total_results: Optional[int] = None
    next_token: Optional[str] = None
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Campaign negative keywords
# ---------------------------------------------------------------------------

class CreateNegativeKeywordResponse(BaseModel):
    success: bool
    keyword_id: Optional[str] = None
    message: str
    details: Optional[Dict[str, Any]] = None
    error: Optional[Any] = None


class UpdateNegativeKeywordResponse(BaseModel):
    success: bool
    keyword_id: str
    message: str
    updated_fields: Optional[Dict[str, Any]] = None
    details: Optional[Dict[str, Any]] = None
    error: Optional[Any] = None


class NegativeKeywordItem(BaseModel):
    keyword_id: Optional[str] = None
    keyword_text: Optional[str] = None
    match_type: Optional[str] = None
    campaign_id: Optional[str] = None
    ad_group_id: Optional[str] = None
    state: Optional[str] = None


class ListNegativeKeywordsResponse(BaseModel):
    success: bool
    items: List[NegativeKeywordItem] = Field(default_factory=list)
    count: int = 0
    next_token: Optional[str] = None
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Targeting clauses (targets)
# ---------------------------------------------------------------------------

class CreateTargetResponse(BaseModel):
    success: bool
    target_id: Optional[str] = None
    message: str
    details: Optional[Dict[str, Any]] = None
    error: Optional[Any] = None


class UpdateTargetResponse(BaseModel):
    success: bool
    target_id: str
    message: str
    updated_fields: Optional[Dict[str, Any]] = None
    details: Optional[Dict[str, Any]] = None
    error: Optional[Any] = None


class TargetItem(BaseModel):
    target_id: Optional[str] = None
    campaign_id: Optional[str] = None
    ad_group_id: Optional[str] = None
    expression: Optional[List[Dict[str, Any]]] = None
    resolved_expression: Optional[List[Dict[str, Any]]] = None
    expression_type: Optional[str] = None
    state: Optional[str] = None
    bid: Optional[float] = None


class ListTargetsResponse(BaseModel):
    success: bool
    items: List[TargetItem] = Field(default_factory=list)
    count: int = 0
    next_token: Optional[str] = None
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Campaign negative targets
# ---------------------------------------------------------------------------

class CreateNegativeTargetResponse(BaseModel):
    success: bool
    target_id: Optional[str] = None
    message: str
    details: Optional[Dict[str, Any]] = None
    error: Optional[Any] = None


class UpdateNegativeTargetResponse(BaseModel):
    success: bool
    target_id: str
    message: str
    updated_fields: Optional[Dict[str, Any]] = None
    details: Optional[Dict[str, Any]] = None
    error: Optional[Any] = None


class NegativeTargetItem(BaseModel):
    target_id: Optional[str] = None
    campaign_id: Optional[str] = None
    expression: Optional[List[Dict[str, Any]]] = None
    resolved_expression: Optional[List[Dict[str, Any]]] = None
    state: Optional[str] = None


class ListNegativeTargetsResponse(BaseModel):
    success: bool
    items: List[NegativeTargetItem] = Field(default_factory=list)
    count: int = 0
    next_token: Optional[str] = None
    error: Optional[str] = None
