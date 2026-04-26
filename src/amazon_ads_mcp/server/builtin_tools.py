"""Register built-in tools for the MCP server.

Handle registration of identity, profile, region, download, sampling, and
authentication tools depending on the active provider.

Examples
--------
.. code-block:: python

   import asyncio
   from fastmcp import FastMCP
   from amazon_ads_mcp.server.builtin_tools import register_all_builtin_tools

   async def main():
       server = FastMCP("amazon-ads")
       await register_all_builtin_tools(server)

   asyncio.run(main())
"""

import logging
from typing import Dict, Optional

from fastmcp import Context, FastMCP

from fastmcp.dependencies import Progress

from ..auth.manager import get_auth_manager
from ..config.settings import settings
from ..middleware.auth_session_bridge import compute_session_state
from ..models.builtin_responses import (
    ClearProfileResponse,
    DownloadedFile,
    DownloadExportResponse,
    EnableToolGroupResponse,
    GetActiveIdentityResponse,
    GetDownloadUrlResponse,
    GetProfileResponse,
    GetRegionResponse,
    GetSessionStateResponse,
    ListDownloadsResponse,
    ListReportFieldsResponse,
    ListRegionsResponse,
    ProfileSelectorResponse,
    ProfilePageResponse,
    ProfileCacheRefreshResponse,
    ProfileSearchResponse,
    ProfileSummaryResponse,
    ReadDownloadResponse,
    RoutingStateResponse,
    SamplingTestResponse,
    SetContextResponse,
    SetProfileResponse,
    SetRegionResponse,
    ToolGroupInfo,
    ToolGroupsResponse,
)
from ..tools import identity, profile, profile_listing
from ..tools import report_fields
from ..tools import region as region_module
from ..tools.oauth import OAuthTools

# Removed http_client imports - override functions were removed

logger = logging.getLogger(__name__)


_REQUEST_SCOPED_NOTE = (
    "State is request-scoped on this transport; re-establish context "
    "at the start of every block."
)

_TOKEN_SWAPPED_NOTE = (
    "Tenant token rotated mid-session; previous tenant state was "
    "cleared. Re-establish context for the new tenant."
)


def _state_note(state_reason: Optional[str]) -> Optional[str]:
    """Translate a ``state_reason`` code into a human-readable hint."""
    if state_reason == "no_mcp_session":
        return _REQUEST_SCOPED_NOTE
    if state_reason == "token_swapped":
        return _TOKEN_SWAPPED_NOTE
    return None


async def _set_active_identity_impl(
    ctx,
    identity_id: str,
):
    """Module-level implementation of the ``set_active_identity`` tool.

    Extracted so it is unit-testable without a running FastMCP server.
    Populates the three state fields on the response so callers can
    detect request-scoped transports and post-token-swap contexts.
    """
    from ..models import SetActiveIdentityRequest

    req = SetActiveIdentityRequest(identity_id=identity_id)
    response = await identity.set_active_identity(req)

    session_present, state_scope, state_reason = compute_session_state(ctx)
    response.session_present = session_present
    response.state_scope = state_scope
    response.state_reason = state_reason

    note = _state_note(state_reason)
    if note and not response.message:
        response.message = note
    return response


async def _set_context_impl(
    ctx,
    identity_id: Optional[str] = None,
    region: Optional[str] = None,
    region_code: Optional[str] = None,
    profile_id: Optional[str] = None,
) -> SetContextResponse:
    """Module-level implementation of the ``set_context`` tool.

    Extracted so it is unit-testable without a running FastMCP server.
    Always returns the three state fields so clients can decide
    whether to re-issue ``set_context`` every block.
    """
    if not any([identity_id, region, region_code, profile_id]):
        raise ValueError(
            "set_context requires at least one of: "
            "identity_id, region/region_code, profile_id"
        )

    session_present, state_scope, state_reason = compute_session_state(ctx)

    if identity_id:
        from ..models import SetActiveIdentityRequest

        await identity.set_active_identity(
            SetActiveIdentityRequest(identity_id=identity_id)
        )

    requested_region = region or region_code
    if requested_region:
        region_result = await region_module.set_region(requested_region)
        if not region_result.get("success", False):
            return SetContextResponse(
                success=False,
                identity_id=identity_id,
                profile_id=profile_id,
                region=requested_region,
                error=region_result.get("error"),
                message=region_result.get("message"),
                session_present=session_present,
                state_scope=state_scope,
                state_reason=state_reason,
            )

    if profile_id:
        await profile.set_active_profile(profile_id)

    active_identity = await identity.get_active_identity()
    active_region = await region_module.get_region()
    active_profile = await profile.get_active_profile()

    note = _state_note(state_reason)
    message = "Context updated" + (f"; {note}" if note else "")

    return SetContextResponse(
        success=True,
        identity_id=active_identity.id if active_identity else None,
        region=active_region.get("region"),
        profile_id=active_profile.get("profile_id"),
        message=message,
        session_present=session_present,
        state_scope=state_scope,
        state_reason=state_reason,
    )


async def _get_active_identity_impl(ctx) -> GetActiveIdentityResponse:
    """Module-level implementation of the ``get_active_identity`` tool.

    Wraps the raw active ``Identity`` (or ``None``) in a response model
    that carries the three state fields so agents can use this as a
    cheap session-scope probe.

    Note: this is a small breaking change from the prior shape (the
    tool used to return the raw ``Identity``). See
    :class:`amazon_ads_mcp.models.builtin_responses.GetActiveIdentityResponse`
    for the new shape.
    """
    active_identity = await identity.get_active_identity()
    session_present, state_scope, state_reason = compute_session_state(ctx)

    identity_payload = active_identity.model_dump() if active_identity else None
    message = (
        None
        if active_identity
        else "No active identity set; call set_active_identity or set_context."
    )

    return GetActiveIdentityResponse(
        success=True,
        identity=identity_payload,
        message=message,
        session_present=session_present,
        state_scope=state_scope,
        state_reason=state_reason,
    )


async def _get_active_profile_impl(ctx) -> GetProfileResponse:
    """Module-level implementation of the ``get_active_profile`` tool.

    Decorates the existing profile lookup with the three state fields
    so it doubles as a state-scope probe.
    """
    result = await profile.get_active_profile()
    session_present, state_scope, state_reason = compute_session_state(ctx)
    return GetProfileResponse(
        **result,
        session_present=session_present,
        state_scope=state_scope,
        state_reason=state_reason,
    )


async def _get_routing_state_impl(ctx) -> RoutingStateResponse:
    """Module-level implementation of the ``get_routing_state`` tool.

    Decorates routing state with the three state fields so it doubles
    as a state-scope probe.
    """
    from ..utils.http_client import get_routing_state as _get_routing_state
    from ..utils.region_config import RegionConfig

    result = _get_routing_state()

    current_region = settings.amazon_ads_region or "na"
    default_host = RegionConfig.get_api_host(current_region)
    if settings.amazon_ads_sandbox_mode:
        default_host = default_host.replace("advertising-api", "advertising-api-test")

    session_present, state_scope, state_reason = compute_session_state(ctx)

    return RoutingStateResponse(
        region=result.get("region", current_region),
        host=result.get("host", default_host),
        headers=result.get("headers", {}),
        sandbox=settings.amazon_ads_sandbox_mode,
        session_present=session_present,
        state_scope=state_scope,
        state_reason=state_reason,
    )


async def _get_session_state_impl(ctx) -> GetSessionStateResponse:
    """Read-only probe: return ``(session_present, state_scope, state_reason)``.

    Performs no I/O, does not touch the auth manager, and does not
    mutate any ContextVar. Designed to be called once per ``execute``
    block as the cheapest possible state-scope probe.
    """
    session_present, state_scope, state_reason = compute_session_state(ctx)
    return GetSessionStateResponse(
        session_present=session_present,
        state_scope=state_scope,
        state_reason=state_reason,
    )


# ---------------------------------------------------------------------------
# Shared description fragments (state-scope contract — keep in sync with
# code_mode.EXECUTE_DESCRIPTION and GetSessionStateResponse docstring).
# ---------------------------------------------------------------------------

_STATE_SCOPE_RULE = (
    "Re-establish context before the next tool call iff "
    "`state_scope == 'request'` or `state_reason` is not null."
)

_STATE_SCOPE_PROBE_HINT = (
    "Probe the transport once per block via `get_session_state`; the "
    "scope cannot change within a block, so one probe per block is "
    "sufficient."
)

_STATE_REASON_VALUES = (
    "`state_reason` is `null` on the happy path. When non-null it "
    "takes one of:\n"
    "- `\"no_mcp_session\"` — the transport has no long-lived MCP "
    "session (e.g. stateless HTTP). `state_scope` will be `'request'`.\n"
    "- `\"token_swapped\"` — the transport DOES support sessions, but "
    "a different bearer/refresh token arrived mid-session and the "
    "previous tenant's identity, credentials, and profile were "
    "cleared. `state_scope` stays `'session'` but you must "
    "re-establish context for the new tenant before the next call.\n"
    "- `\"bridge_unavailable\"` — reserved; the session bridge ran "
    "but could not persist state. Treat as `'request'`."
)

_TOKEN_SWAPPED_SUBTLETY = (
    "Note: `token_swapped` is the rare edge case where `state_scope` "
    "remains `'session'` but context was cleared mid-session — the "
    "combined rule above handles this correctly, do not rely on "
    "scope alone."
)


def _state_aware_description(action: str) -> str:
    """Build a tool description for a stateful tool.

    ``action`` is the one-line description of what the tool does.
    The state-scope contract block is appended verbatim so every
    tool surfaces the same rule and the same enumerated reasons.
    """
    return (
        f"{action}\n\n"
        f"{_STATE_SCOPE_RULE} {_STATE_SCOPE_PROBE_HINT}\n\n"
        f"{_STATE_REASON_VALUES}\n\n"
        f"{_TOKEN_SWAPPED_SUBTLETY}"
    )


async def register_identity_tools(server: FastMCP):
    """Register identity management tools.

    :param server: FastMCP server instance.
    """

    @server.tool(
        name="set_active_identity",
        description=_state_aware_description(
            "Set the active identity for Amazon Ads API calls."
        ),
    )
    async def set_active_identity_tool(
        ctx: Context,
        identity_id: str,
    ):
        """Set the active identity for API calls."""
        return await _set_active_identity_impl(ctx, identity_id)

    @server.tool(
        name="get_active_identity",
        description=(
            "Get the currently active identity. Doubles as a "
            "session-scope probe: the response includes "
            "`session_present`, `state_scope`, and `state_reason` so "
            "agents can detect whether previously-set context "
            "survived to this call."
        ),
    )
    async def get_active_identity_tool(ctx: Context) -> GetActiveIdentityResponse:
        """Get the currently active identity with state-scope metadata."""
        return await _get_active_identity_impl(ctx)

    @server.tool(name="list_identities", description="List all available identities")
    async def list_identities_tool(ctx: Context) -> dict:
        """List all available identities."""
        return await identity.list_identities()

    @server.tool(
        name="get_session_state",
        description=(
            "Read-only probe: returns `{session_present, state_scope, "
            "state_reason}` for the current transport. No side "
            "effects, no auth/network I/O — call this once at the "
            "start of an `execute` block to learn how to manage "
            "context.\n\n"
            f"{_STATE_SCOPE_RULE} {_STATE_SCOPE_PROBE_HINT}\n\n"
            f"{_STATE_REASON_VALUES}\n\n"
            f"{_TOKEN_SWAPPED_SUBTLETY}"
        ),
    )
    async def get_session_state_tool(ctx: Context) -> GetSessionStateResponse:
        """Return the three state fields with no side effects."""
        return await _get_session_state_impl(ctx)

    @server.tool(
        name="set_context",
        description=_state_aware_description(
            "Set active context (identity, region, and/or profile) in "
            "one call. Any subset of `identity_id`, `region` (or "
            "legacy `region_code`), and `profile_id` is allowed."
        ),
    )
    async def set_context_tool(
        ctx: Context,
        identity_id: Optional[str] = None,
        region: Optional[str] = None,
        region_code: Optional[str] = None,
        profile_id: Optional[str] = None,
    ) -> SetContextResponse:
        """Set identity, region, and profile context in one call."""
        return await _set_context_impl(
            ctx,
            identity_id=identity_id,
            region=region,
            region_code=region_code,
            profile_id=profile_id,
        )


async def register_profile_tools(server: FastMCP):
    """Register profile management tools.

    :param server: FastMCP server instance.
    """

    @server.tool(
        name="set_active_profile",
        description=_state_aware_description(
            "Set the active profile ID for Amazon Ads API calls."
        ),
    )
    async def set_active_profile_tool(
        ctx: Context, profile_id: str
    ) -> SetProfileResponse:
        """Set the active profile ID."""
        result = await profile.set_active_profile(profile_id)
        return SetProfileResponse(**result)

    @server.tool(
        name="get_active_profile",
        description=(
            "Get the currently active profile ID. Doubles as a "
            "session-scope probe: the response includes "
            "`session_present`, `state_scope`, and `state_reason` so "
            "agents can detect whether previously-set context "
            "survived to this call."
        ),
    )
    async def get_active_profile_tool(ctx: Context) -> GetProfileResponse:
        """Get the currently active profile ID with state-scope metadata."""
        return await _get_active_profile_impl(ctx)

    @server.tool(
        name="clear_active_profile",
        description=_state_aware_description(
            "Clear the active profile ID, falling back to the default."
        ),
    )
    async def clear_active_profile_tool(ctx: Context) -> ClearProfileResponse:
        """Clear the active profile ID."""
        result = await profile.clear_active_profile()
        return ClearProfileResponse(**result)

    @server.tool(
        name="select_profile",
        description="Interactively select a profile from available options",
    )
    async def select_profile_tool(ctx: Context) -> ProfileSelectorResponse:
        """Interactively select an Amazon Ads profile.

        This tool uses MCP elicitation to present available profiles to the user
        and let them select one interactively. This is more user-friendly than
        requiring users to call list_profiles and set_active_profile separately.

        The tool will:
        1. Fetch available profiles from the Amazon Ads API
        2. Present them to the user via elicitation
        3. Set the selected profile as active
        4. Return the selection result
        """
        from dataclasses import dataclass

        from ..tools import profile_listing

        # Define the selection structure for elicitation
        @dataclass
        class ProfileSelection:
            profile_id: str

        # Fetch available profiles
        try:
            profiles_data, stale = await profile_listing.get_profiles_cached()
        except Exception as e:
            logger.error(f"Failed to fetch profiles: {e}")
            return ProfileSelectorResponse(
                success=False,
                action="cancel",
                message=f"Failed to fetch profiles: {e}",
            )

        if not profiles_data:
            return ProfileSelectorResponse(
                success=False,
                action="cancel",
                message="No profiles available. Please ensure you have access to advertising accounts.",
            )

        if len(profiles_data) > profile_listing.PROFILE_SELECTION_THRESHOLD:
            message = (
                "Too many profiles to display here. Use summarize_profiles, "
                "search_profiles, or page_profiles to locate the right profile."
            )
            if stale:
                message = "Using cached profile list; data may be stale. " + message
            return ProfileSelectorResponse(
                success=True,
                action="cancel",
                message=message,
            )

        # Build a formatted message with profile options
        profile_list = []
        for p in profiles_data:
            profile_id = str(p.get("profileId", ""))
            country = p.get("countryCode", "")
            account_info = p.get("accountInfo", {})
            account_name = account_info.get("name", "Unknown")
            account_type = account_info.get("type", "Unknown")
            profile_list.append(
                f"  - {profile_id}: {account_name} ({country}, {account_type})"
            )

        profiles_message = (
            f"Available profiles ({len(profiles_data)} found):\n"
            + "\n".join(profile_list)
            + "\n\nEnter the profile ID you want to use:"
        )

        # Use elicitation to let user select
        try:
            result = await ctx.elicit(
                message=profiles_message,
                response_type=ProfileSelection,
            )

            if result.action == "accept":
                selected_id = result.data.profile_id

                # Validate the selection
                valid_ids = [str(p.get("profileId", "")) for p in profiles_data]
                if selected_id not in valid_ids:
                    return ProfileSelectorResponse(
                        success=False,
                        action="accept",
                        message=f"Invalid profile ID: {selected_id}. Please select from the available profiles.",
                    )

                # Set the selected profile as active
                await profile.set_active_profile(selected_id)

                # Find the profile name for the response
                selected_profile = next(
                    (p for p in profiles_data if str(p.get("profileId")) == selected_id),
                    None,
                )
                profile_name = (
                    selected_profile.get("accountInfo", {}).get("name", "Unknown")
                    if selected_profile
                    else "Unknown"
                )

                return ProfileSelectorResponse(
                    success=True,
                    action="accept",
                    profile_id=selected_id,
                    profile_name=profile_name,
                    message=f"Profile '{profile_name}' ({selected_id}) is now active.",
                )

            elif result.action == "decline":
                return ProfileSelectorResponse(
                    success=True,
                    action="decline",
                    message="Profile selection declined. No changes made.",
                )

            else:  # cancel
                return ProfileSelectorResponse(
                    success=True,
                    action="cancel",
                    message="Profile selection cancelled.",
                )

        except Exception as e:
            logger.error(f"Elicitation failed: {e}")
            return ProfileSelectorResponse(
                success=False,
                action="cancel",
                message=f"Profile selection failed: {e}",
            )


async def register_profile_listing_tools(server: FastMCP):
    """Register profile listing tools with bounded responses."""

    @server.tool(
        name="summarize_profiles",
        description=(
            "List profiles (summary mode): aggregate counts by country "
            "and account type. Use when you need to know what profile "
            "kinds exist without enumerating individual records."
        ),
    )
    async def summarize_profiles_tool(ctx: Context) -> ProfileSummaryResponse:
        """List profiles in summary mode."""
        result = await profile_listing.summarize_profiles()
        return ProfileSummaryResponse(**result)

    @server.tool(
        name="search_profiles",
        description=(
            "List profiles (search mode): filter by name (`query`), "
            "`country_code`, or `account_type`, with bounded `limit`. "
            "Use when you know what you're looking for and want a "
            "focused result set."
        ),
    )
    async def search_profiles_tool(
        ctx: Context,
        query: Optional[str] = None,
        country_code: Optional[str] = None,
        account_type: Optional[str] = None,
        limit: int = profile_listing.DEFAULT_SEARCH_LIMIT,
    ) -> ProfileSearchResponse:
        """List profiles in search mode (filtered, bounded)."""
        result = await profile_listing.search_profiles(
            query=query,
            country_code=country_code,
            account_type=account_type,
            limit=limit,
        )
        return ProfileSearchResponse(**result)

    @server.tool(
        name="page_profiles",
        description=(
            "List profiles (paged mode): paginated read with `offset` "
            "and `limit`. Returns `{items, total_count, has_more, "
            "next_offset}`. Use when iterating across the full set "
            "without dumping everything at once."
        ),
    )
    async def page_profiles_tool(
        ctx: Context,
        country_code: Optional[str] = None,
        account_type: Optional[str] = None,
        offset: int = 0,
        limit: int = profile_listing.DEFAULT_PAGE_LIMIT,
    ) -> ProfilePageResponse:
        """List profiles in paged mode."""
        result = await profile_listing.page_profiles(
            country_code=country_code,
            account_type=account_type,
            offset=offset,
            limit=limit,
        )
        return ProfilePageResponse(**result)

    @server.tool(
        name="refresh_profiles_cache",
        description=(
            "List profiles (cache refresh): force re-fetch of cached "
            "profiles for the current identity and region. Use when "
            "you suspect cached data is stale before the next "
            "summarize/search/page call."
        ),
    )
    async def refresh_profiles_cache_tool(ctx: Context) -> ProfileCacheRefreshResponse:
        """Force refresh the cached profile list."""
        result = await profile_listing.refresh_profiles_cache()
        return ProfileCacheRefreshResponse(**result)


async def register_region_tools(server: FastMCP):
    """Register region management tools.

    :param server: FastMCP server instance.
    """

    @server.tool(
        name="set_region",
        description=_state_aware_description(
            "Set the region for Amazon Ads API calls. Pass `region` "
            "(preferred) or `region_code` (legacy alias). Valid "
            "values: 'na', 'eu', 'fe'."
        ),
    )
    async def set_region_tool(
        ctx: Context,
        region: Optional[str] = None,
        region_code: Optional[str] = None,
    ) -> SetRegionResponse:
        """Set the region for API calls. Accepts legacy `region_code` alias.

        Bad input is reported as ``mcp_input_validation`` with alias-aware
        hints so agents recover with one targeted retry instead of getting
        ``internal_error`` and a generic message.
        """
        from ..exceptions import ValidationError as _AdsValidationError

        value = region or region_code
        if not value:
            raise _AdsValidationError(
                "set_region requires `region` (or legacy `region_code`).",
                field="region",
                value=None,
            )
        try:
            result = await region_module.set_region(value)
        except ValueError as exc:
            # Convert the bare ValueError raised by set_active_region into a
            # typed validation error so the envelope translator routes it as
            # ``mcp_input_validation`` with alias-aware hints.
            hints = _build_set_region_hints(value)
            err = _AdsValidationError(
                str(exc) or "Invalid region.",
                field="region",
                value=value,
            )
            # Translator surfaces custom hints from details["hints"] if present.
            err.details["hints"] = hints
            raise err from exc
        return SetRegionResponse(**result)

    @server.tool(name="get_region", description="Get the current region setting")
    async def get_region_tool(ctx: Context) -> GetRegionResponse:
        """Get the current region."""
        result = await region_module.get_region()
        return GetRegionResponse(**result)

    @server.tool(name="list_regions", description="List all available regions")
    async def list_regions_tool(ctx: Context) -> ListRegionsResponse:
        """List available regions."""
        result = await region_module.list_regions()
        return ListRegionsResponse(**result)

    @server.tool(
        name="get_routing_state",
        description=(
            "Get the current routing state (region, host, headers). "
            "Doubles as a session-scope probe: the response includes "
            "`session_present`, `state_scope`, and `state_reason` so "
            "agents can detect whether previously-set context "
            "survived to this call."
        ),
    )
    async def get_routing_state_tool(ctx: Context) -> RoutingStateResponse:
        """Get routing state with state-scope metadata."""
        return await _get_routing_state_impl(ctx)


# Removed region_identity_tools - list_identities_by_region was just a convenience wrapper


# Routing override tools removed - use the main region/marketplace tools instead


async def register_download_tools(server: FastMCP):
    """Register download management tools.

    :param server: FastMCP server instance
    :type server: FastMCP
    """

    # Background task with progress reporting for long-running downloads
    # task=True is inherited from server-wide tasks=True setting
    @server.tool(
        name="download_export",
        description="Download a completed export to local storage (supports background execution)",
    )
    async def download_export_tool(
        ctx: Context,
        export_id: str,
        export_url: str,
        progress: Progress = Progress(),  # Inject progress tracker
    ) -> DownloadExportResponse:
        """Download a completed export to local storage.

        This tool supports background execution with progress reporting.
        When called with task=True by the client, it returns immediately
        with a task ID while the download continues in the background.
        """
        import base64

        from ..utils.export_download_handler import get_download_handler

        # Report progress: starting download
        await progress.set_total(3)  # 3 steps: parse, download, complete
        await progress.set_message("Parsing export metadata...")
        await progress.increment()

        handler = get_download_handler()

        # Get active profile for scoped storage
        auth_mgr = get_auth_manager()
        profile_id = auth_mgr.get_active_profile_id() if auth_mgr else None
        if not profile_id:
            raise ValueError(
                "No active profile set. Call set_active_profile or set_context first."
            )

        # Determine export type from ID
        try:
            padded = export_id + "=" * (4 - len(export_id) % 4)
            decoded = base64.b64decode(padded).decode("utf-8")
            if "," in decoded:
                _, suffix = decoded.rsplit(",", 1)
                type_map = {
                    "C": "campaigns",
                    "A": "adgroups",
                    "AD": "ads",
                    "T": "targets",
                }
                export_type = type_map.get(suffix.upper(), "general")
            else:
                export_type = "general"
        except (AttributeError, TypeError, ValueError):
            export_type = "general"

        # Report progress: downloading
        await progress.set_message(f"Downloading {export_type} export...")
        await progress.increment()

        file_path = await handler.download_export(
            export_url=export_url,
            export_id=export_id,
            export_type=export_type,
            profile_id=profile_id,
        )

        # Report progress: complete
        await progress.set_message("Download complete!")
        await progress.increment()

        return DownloadExportResponse(
            success=True,
            file_path=str(file_path),
            export_type=export_type,
            message=f"Export downloaded to {file_path}",
        )

    @server.tool(
        name="list_downloads",
        description="List all downloaded exports and reports for the active profile",
    )
    async def list_downloads_tool(
        ctx: Context, resource_type: Optional[str] = None
    ) -> ListDownloadsResponse:
        """List downloaded files for the active profile."""
        from ..tools.download_tools import list_downloaded_files

        # Get active profile for scoped listing
        auth_mgr = get_auth_manager()
        profile_id = auth_mgr.get_active_profile_id() if auth_mgr else None

        result = await list_downloaded_files(resource_type, profile_id=profile_id)

        # Transform flat file list into DownloadedFile objects
        files = []
        for f in result.get("files", []):
            # Extract resource_type from path (e.g., "exports/campaigns/file.json")
            path_parts = f.get("path", "").split("/")
            rtype = path_parts[0] if path_parts else "unknown"

            files.append(
                DownloadedFile(
                    filename=f.get("name", ""),
                    path=f.get("path", ""),
                    size=f.get("size", 0),
                    modified=f.get("modified", ""),
                    resource_type=rtype,
                )
            )

        return ListDownloadsResponse(
            success=True,
            files=files,
            count=result.get("total_files", len(files)),
            download_dir=result.get("base_directory", ""),
        )

    @server.tool(
        name="get_download_url",
        description="""Get the HTTP URL for downloading a file.

Use with list_downloads to find available files, then get their download URLs.
The URL can be opened in a browser or used with curl/wget to download the file.

Note: Requires HTTP transport (not stdio).
""",
    )
    async def get_download_url_tool(
        ctx: Context,
        file_path: Optional[str] = None,
        filename: Optional[str] = None,
    ) -> GetDownloadUrlResponse:
        """Generate the download URL for a file.

        :param ctx: MCP context
        :param file_path: Relative path from list_downloads output
        :return: Response with download URL
        """
        from pathlib import Path
        from urllib.parse import quote

        requested_path = file_path or filename
        if not requested_path:
            return GetDownloadUrlResponse(
                success=False,
                error="Missing required argument",
                hint="Provide `file_path` (or legacy alias `filename`)",
            )

        # Try to get HTTP request context
        try:
            from fastmcp.server.dependencies import get_http_request

            request = get_http_request()
        except (ImportError, RuntimeError):
            return GetDownloadUrlResponse(
                success=False,
                error="HTTP transport required for file downloads",
                hint="Run server with --transport http",
            )

        # Get current profile
        auth_mgr = get_auth_manager()
        profile_id = auth_mgr.get_active_profile_id() if auth_mgr else None

        if not profile_id:
            return GetDownloadUrlResponse(
                success=False,
                error="No active profile",
                hint="Set active profile before getting download URLs",
            )

        # Validate file exists and stays inside the active profile's dir
        from ..utils.export_download_handler import get_download_handler
        from ..utils.paths import PathTraversalError, safe_join_within

        handler = get_download_handler()
        profile_dir = handler.base_dir / "profiles" / profile_id
        try:
            full_path = safe_join_within(profile_dir, requested_path)
        except PathTraversalError:
            return GetDownloadUrlResponse(
                success=False,
                error="Invalid file path",
                hint="Paths must be relative and stay within the active profile's directory",
            )

        if not full_path.exists():
            return GetDownloadUrlResponse(
                success=False,
                error="File not found",
                hint="Use list_downloads to see available files",
            )

        # Build URL with proper encoding
        base_url = str(request.base_url).rstrip("/")

        # Handle forwarded headers from reverse proxy
        forwarded_proto = request.headers.get("X-Forwarded-Proto")
        forwarded_host = request.headers.get("X-Forwarded-Host")
        if forwarded_proto and forwarded_host:
            base_url = f"{forwarded_proto}://{forwarded_host}"

        # URL-encode path segments
        encoded_path = "/".join(
            quote(part, safe="") for part in Path(requested_path).parts
        )

        download_url = f"{base_url}/downloads/p/{profile_id}/{encoded_path}"
        return GetDownloadUrlResponse(
            success=True,
            download_url=download_url,
            file_name=full_path.name,
            size_bytes=full_path.stat().st_size,
            profile_id=profile_id,
            instructions=(
                f"Use HTTP GET to download: curl -O '{download_url}'. "
                "If authentication is enabled, add header: "
                "Authorization: Bearer <token>"
            ),
        )

    @server.tool(
        name="read_download",
        description=(
            "Read a profile-scoped downloaded file directly from server storage. "
            "Use `list_downloads` to get a `file_path` first."
        ),
    )
    async def read_download_tool(
        ctx: Context,
        file_path: str,
        offset: int = 0,
        length: int = 65536,
        encoding: Optional[str] = "utf-8",
    ) -> ReadDownloadResponse:
        """Read part of a downloaded file for the active profile."""
        import base64

        from ..utils.export_download_handler import get_download_handler
        from ..utils.paths import PathTraversalError, safe_join_within

        if offset < 0:
            return ReadDownloadResponse(
                success=False,
                error="Invalid offset",
                hint="offset must be >= 0",
            )
        if length <= 0 or length > 1_000_000:
            return ReadDownloadResponse(
                success=False,
                error="Invalid length",
                hint="length must be between 1 and 1000000 bytes",
            )

        auth_mgr = get_auth_manager()
        profile_id = auth_mgr.get_active_profile_id() if auth_mgr else None
        if not profile_id:
            return ReadDownloadResponse(
                success=False,
                error="No active profile",
                hint="Set active profile before reading downloads",
            )

        handler = get_download_handler()
        profile_dir = handler.base_dir / "profiles" / profile_id

        try:
            full_path = safe_join_within(profile_dir, file_path)
        except PathTraversalError:
            return ReadDownloadResponse(
                success=False,
                error="Invalid file path",
                hint="Paths must be relative and stay within the active profile's directory",
            )

        if not full_path.exists() or not full_path.is_file():
            return ReadDownloadResponse(
                success=False,
                error="File not found",
                hint="Use list_downloads to see available files",
            )

        size_bytes = full_path.stat().st_size
        if offset >= size_bytes:
            return ReadDownloadResponse(
                success=False,
                error="Offset out of range",
                hint=f"File size is {size_bytes} bytes",
            )

        with open(full_path, "rb") as f:
            f.seek(offset)
            data = f.read(length)

        bytes_read = len(data)
        truncated = (offset + bytes_read) < size_bytes

        if encoding:
            try:
                content = data.decode(encoding)
                return ReadDownloadResponse(
                    success=True,
                    file_path=file_path,
                    profile_id=profile_id,
                    offset=offset,
                    bytes_read=bytes_read,
                    size_bytes=size_bytes,
                    truncated=truncated,
                    encoding=encoding,
                    content=content,
                )
            except UnicodeDecodeError:
                return ReadDownloadResponse(
                    success=True,
                    file_path=file_path,
                    profile_id=profile_id,
                    offset=offset,
                    bytes_read=bytes_read,
                    size_bytes=size_bytes,
                    truncated=truncated,
                    encoding=None,
                    content_base64=base64.b64encode(data).decode("ascii"),
                    hint="Could not decode bytes with requested encoding; returning base64",
                )

        return ReadDownloadResponse(
            success=True,
            file_path=file_path,
            profile_id=profile_id,
            offset=offset,
            bytes_read=bytes_read,
            size_bytes=size_bytes,
            truncated=truncated,
            encoding=None,
            content_base64=base64.b64encode(data).decode("ascii"),
        )


async def register_report_catalog_tools(server: FastMCP):
    """Register report field catalog tools.

    Always registers ``list_report_fields`` (baseline, unchanged since the
    regression fence in adsv1.md §E.1). Conditionally registers
    ``report_fields`` (v1 catalog query + validate) and the debug helper
    ``_report_fields_debug`` based on env-gated settings.
    """

    @server.tool(
        name="list_report_fields",
        description=(
            "List valid report fields by report operation. "
            "Call with no args to list supported operations."
        ),
    )
    async def list_report_fields_tool(
        ctx: Context,
        operation: Optional[str] = None,
    ) -> ListReportFieldsResponse:
        """Return curated report field catalogs."""
        result = report_fields.get_report_fields_catalog(operation=operation)
        return ListReportFieldsResponse(**result)

    if settings.enable_report_fields_tool:
        # Imports are local so disabling the tool doesn't pay the handler
        # import cost at server startup.
        from ..models.builtin_responses import (  # noqa: F401
            QueryReportFieldsResponse,
            ValidateReportFieldsResponse,
        )
        from ..tools.report_fields_v1_handler import (
            ReportFieldsToolError,
            _apply_drop_to_payload,
            handle as report_fields_handle,
        )

        @server.tool(
            name="report_fields",
            description=(
                "Query or validate Ads API v1 report fields against the "
                "packaged v1 catalog. Use mode='query' to discover fields "
                "(category, search, compatible_with, requires, fields "
                "detail lookup with pagination) or mode='validate' to "
                "pre-flight a field list before AdsApiv1CreateReport. "
                "See list_report_fields for the minimal baseline and "
                "other report APIs (rp_*, br_*, mmm_*). "
                "Response.stale_warning is a string when the catalog "
                "parse timestamp is older than LIST_REPORT_FIELDS_STALE_DAYS "
                "(default 90) and null otherwise. Set that env var lower in "
                "staging/dev to surface stale-catalog warnings earlier. "
                "Optional `drop=[<key>,...]` (query-mode only) strips named "
                "top-level keys from every field record — useful for slimming "
                "the payload when compatibility arrays aren't needed (e.g. "
                "drop=['compatible_dimensions','incompatible_dimensions']). "
                "Values are validated against the record-key allowlist; "
                "typos and unknown keys raise INVALID_MODE_ARGS rather than "
                "silently keeping bytes (the error message surfaces the full "
                "list of droppable keys, so a bad call self-documents the "
                "valid options). Passing drop in mode='validate' is also "
                "rejected — validate carries no field records to shape."
            ),
        )
        async def report_fields_tool(
            ctx: Context,
            mode: str,
            operation: str = "allv1_AdsApiv1CreateReport",
            category: Optional[str] = None,
            search: Optional[str] = None,
            compatible_with: Optional[list] = None,
            requires: Optional[list] = None,
            fields: Optional[list] = None,
            include_v3_mapping: bool = False,
            limit: int = 25,
            offset: int = 0,
            validate_fields: Optional[list] = None,
            drop: Optional[list] = None,
        ):
            """Dispatch to the query/validate handler.

            Serializes with exclude_none=True so optional fields the caller
            hasn't requested (e.g. v3_name_dsp when include_v3_mapping=False)
            drop from the wire payload rather than serializing as `null`.
            Matches the byte-cap serializer's policy so wire-level and
            byte-measured payload shapes agree.

            When *drop* is provided, the handler factors it into byte-cap
            measurement and the wrapper strips the named keys from each
            field record after dump. Validate-mode payloads have no field
            records and pass through unchanged.
            """
            try:
                result = report_fields_handle(
                    mode=mode,
                    operation=operation,
                    category=category,
                    search=search,
                    compatible_with=compatible_with,
                    requires=requires,
                    fields=fields,
                    include_v3_mapping=include_v3_mapping,
                    limit=limit,
                    offset=offset,
                    validate_fields=validate_fields,
                    drop=drop,
                )
                payload = result.model_dump(exclude_none=True)
                if drop:
                    _apply_drop_to_payload(payload, set(drop))
                return payload
            except ReportFieldsToolError as exc:
                # Re-raise as typed ValidationError so the envelope translator
                # classifies as mcp_input_validation (not internal_error).
                # ReportFieldsToolError carries a stable .code from
                # ReportFieldsErrorCode — preserve it in details so callers can
                # branch on it.
                from ..utils.errors import ValidationError as _ValidationError

                err = _ValidationError(str(exc), field=None)
                err.details["error_code"] = exc.code.value
                raise err from exc

    if settings.amazon_ads_debug_tools:
        from ..tools import report_fields_v1_catalog as _rf_catalog

        @server.tool(
            name="_report_fields_debug",
            description=(
                "Internal: return loaded catalog schema_version, parsed_at, "
                "entry counts, and source_commit. Hidden unless "
                "AMAZON_ADS_DEBUG_TOOLS=true."
            ),
        )
        async def _report_fields_debug_tool(ctx: Context) -> dict:
            try:
                meta = _rf_catalog.get_catalog_meta()
                dims = _rf_catalog.get_dimensions()
                metrics = _rf_catalog.get_metrics()
                return {
                    "success": True,
                    "schema_version": meta.get("schema_version"),
                    "parsed_at": meta.get("parsed_at"),
                    "source_commit": meta.get("source_commit"),
                    "dimensions": len(dims),
                    "metrics": len(metrics),
                }
            except Exception as exc:
                return {"success": False, "error": str(exc)}


async def register_sampling_tools(server: FastMCP):
    """Register sampling tools if sampling is enabled.

    :param server: FastMCP server instance
    :type server: FastMCP
    """
    if not settings.enable_sampling:
        return

    @server.tool(
        name="test_sampling",
        description="Test LLM sampling functionality via MCP client",
    )
    async def test_sampling_tool(
        ctx: Context,
        message: str = "Hello, please summarize this test message",
    ) -> SamplingTestResponse:
        """Test the native MCP sampling functionality.

        Uses FastMCP 2.14.1+ native ctx.sample() directly. This requires
        the MCP client to support sampling (createMessage capability).

        The sampling flow:
        1. Tool sends sampling request to client via ctx.sample()
        2. Client's LLM generates a response
        3. Response is returned to the tool

        Note: If the client doesn't support sampling, an error will be returned.
        Server-side fallback is available when SAMPLING_ENABLED=true and
        OPENAI_API_KEY is configured.
        """
        try:
            # Use native ctx.sample() - FastMCP 2.14.1+
            result = await ctx.sample(
                messages=message,
                system_prompt="You are a helpful assistant. Provide a brief summary.",
                temperature=0.7,
                max_tokens=100,
            )

            # Extract text from result
            response_text = result.text if hasattr(result, "text") else str(result)

            return SamplingTestResponse(
                success=True,
                message="Sampling executed successfully via native ctx.sample()",
                response=response_text,
                sampling_enabled=settings.enable_sampling,
            )
        except Exception as e:
            error_msg = str(e).lower()

            # Check if it's a "client doesn't support sampling" error
            if "does not support sampling" in error_msg or "sampling not supported" in error_msg:
                # Try server-side fallback if enabled
                if settings.enable_sampling:
                    try:
                        from ..utils.sampling_helpers import sample_with_fallback

                        result = await sample_with_fallback(
                            ctx=ctx,
                            messages=message,
                            system_prompt="You are a helpful assistant. Provide a brief summary.",
                            temperature=0.7,
                            max_tokens=100,
                        )
                        response_text = result.text if hasattr(result, "text") else str(result)

                        return SamplingTestResponse(
                            success=True,
                            message="Sampling executed via server-side fallback",
                            response=response_text,
                            sampling_enabled=True,
                            used_fallback="Server-side OpenAI fallback was used",
                        )
                    except Exception as fallback_error:
                        logger.error(f"Server-side fallback failed: {fallback_error}")
                        return SamplingTestResponse(
                            success=False,
                            error=f"Both client and server sampling failed: {fallback_error}",
                            sampling_enabled=True,
                            note="Check OPENAI_API_KEY environment variable",
                        )

                return SamplingTestResponse(
                    success=False,
                    error="Client does not support sampling",
                    sampling_enabled=False,
                    note="Enable server-side fallback with SAMPLING_ENABLED=true and OPENAI_API_KEY",
                )

            logger.error(f"Sampling test failed: {e}")
            return SamplingTestResponse(
                success=False,
                error=str(e),
                sampling_enabled=settings.enable_sampling,
            )


async def register_oauth_tools_builtin(server: FastMCP):
    """Register OAuth authentication tools.

    :param server: FastMCP server instance.
    """
    oauth = OAuthTools(settings)

    @server.tool(
        name="start_oauth_flow",
        description="Start the OAuth authorization flow for Amazon Ads API",
    )
    async def start_oauth_flow(ctx: Context):
        """Start the OAuth authorization flow."""
        return await oauth.start_oauth_flow(ctx)

    @server.tool(
        name="check_oauth_status",
        description="Check the current OAuth authentication status",
    )
    async def check_oauth_status(ctx: Context):
        """Check OAuth authentication status."""
        return await oauth.check_oauth_status(ctx)

    @server.tool(
        name="refresh_oauth_token",
        description="Manually refresh the OAuth access token",
    )
    async def refresh_oauth_token(ctx: Context):
        """Refresh OAuth access token."""
        return await oauth.refresh_access_token(ctx)

    @server.tool(
        name="clear_oauth_tokens",
        description="Clear all stored OAuth tokens and state",
    )
    async def clear_oauth_tokens(ctx: Context):
        """Clear OAuth tokens."""
        return await oauth.clear_oauth_tokens(ctx)

    logger.info("Registered OAuth authentication tools")


# Removed cache tools - not core operations


# Removed diagnostic tools - not core operations


async def register_tool_group_tools(
    server: FastMCP,
    mounted_servers: Dict[str, list],
    group_tool_counts: Optional[Dict[str, int]] = None,
):
    """Register progressive tool disclosure tools.

    These tools let MCP clients discover and selectively enable API tool
    groups, keeping the initial ``tools/list`` response minimal.

    :param server: FastMCP server instance.
    :param mounted_servers: Map of prefix -> list of sub-servers for mounted groups.
    :param group_tool_counts: Pre-counted total tools per group (including disabled).
    """
    _tool_counts = group_tool_counts or {}

    @server.tool(
        name="list_tool_groups",
        description=(
            "List available API tool groups. "
            "Groups are disabled by default; use enable_tool_group to activate."
        ),
    )
    async def list_tool_groups_tool(ctx: Context) -> ToolGroupsResponse:
        """List available tool groups with enable/disable status."""
        groups = []
        total = 0
        enabled_count = 0

        for prefix, sub_servers in mounted_servers.items():
            # Total count from pre-stored values (includes disabled tools)
            count = _tool_counts.get(prefix, 0)
            active = 0
            for sub in sub_servers:
                visible = await sub.list_tools()
                active += len(visible)
            # Fall back to active count if no pre-stored total
            if count == 0 and active > 0:
                count = active
            groups.append(
                ToolGroupInfo(
                    prefix=prefix,
                    tool_count=count,
                    enabled=active > 0,
                )
            )
            total += count
            enabled_count += active

        return ToolGroupsResponse(
            success=True,
            groups=groups,
            total_tools=total,
            enabled_tools=enabled_count,
            message=(
                f"{len(groups)} groups, {enabled_count}/{total} tools enabled. "
                "Use enable_tool_group(prefix) to activate a group."
            ),
        )

    @server.tool(
        name="enable_tool_group",
        description=(
            "Enable or disable an API tool group by prefix. "
            "Call list_tool_groups first to see available groups."
        ),
    )
    async def enable_tool_group_tool(
        ctx: Context,
        prefix: str,
        enable: bool = True,
    ) -> EnableToolGroupResponse:
        """Enable or disable a tool group.

        :param prefix: Tool group prefix (e.g., 'cm', 'dsp').
        :param enable: True to enable, False to disable.
        """
        if prefix not in mounted_servers:
            available = ", ".join(sorted(mounted_servers.keys()))
            return EnableToolGroupResponse(
                success=False,
                prefix=prefix,
                error=f"Unknown group '{prefix}'. Available: {available}",
            )

        affected = 0
        tool_names: list[str] = []
        for sub in mounted_servers[prefix]:
            if enable:
                # Enable first, then list to get visible tools
                sub.enable(components={"tool"})
                tools = await sub.list_tools()
            else:
                # List while visible, then disable
                tools = await sub.list_tools()
                sub.disable(components={"tool"})
            tool_names.extend(f"{prefix}_{t.name}" for t in tools)
            affected += len(tools)

        action = "enabled" if enable else "disabled"
        return EnableToolGroupResponse(
            success=True,
            prefix=prefix,
            enabled=enable,
            tool_count=affected,
            tool_names=sorted(tool_names),
            message=f"{action.capitalize()} {affected} tools in group '{prefix}'.",
        )

    logger.info(
        "Registered tool group tools (%d groups)", len(mounted_servers)
    )


# Alias map for the ``set_region`` validator. Mirrors SP's
# ``_REGION_SUGGESTION_ALIASES`` — common ways agents name a region and the
# canonical SP/Ads code we steer them to.
_REGION_SUGGESTION_ALIASES: Dict[str, str] = {
    "usa": "na",
    "unitedstates": "na",
    "northamerica": "na",
    "america": "na",
    "europe": "eu",
    "europeanunion": "eu",
    "euro": "eu",
    "asia": "fe",
    "apac": "fe",
    "fareast": "fe",
    "asiapacific": "fe",
}


def _build_set_region_hints(invalid_value: Optional[str]) -> list[str]:
    """Return alias-aware hints for an invalid ``set_region`` input.

    Always names the canonical valid set so an agent can recover with one
    targeted retry. When ``invalid_value`` matches a known alias, prepends
    a ``did_you_mean`` hint with the canonical code.
    """
    import re as _re

    hints: list[str] = []
    if isinstance(invalid_value, str) and invalid_value:
        compact = _re.sub(r"[^a-z0-9]+", "", invalid_value.lower())
        suggested = _REGION_SUGGESTION_ALIASES.get(compact)
        if suggested:
            hints.append(
                f"Region {invalid_value!r} is not valid. "
                f"Did you mean region={suggested!r}?"
            )
    hints.append("set_region accepts canonical regions: 'na', 'eu', or 'fe'.")
    return hints


async def register_envelope_contract_tools(server: FastMCP) -> None:
    """Register a read-only probe exposing the cross-server envelope contract.

    Agents can call ``get_envelope_contract`` once at startup to discover
    which contract version this server implements and which ``error_kind``
    values it may emit. See ``openbridge-mcp/CONTRACT.md`` for the canonical
    definition.

    :param server: FastMCP server instance.
    """
    from typing import Any

    from ..middleware.error_envelope import (
        ENVELOPE_VERSION,
        SUPPORTED_ERROR_KINDS,
    )

    @server.tool(
        name="get_envelope_contract",
        description=(
            "Read-only probe: returns the cross-server error envelope contract "
            "this server implements (contract_version, error_kinds, normalized_kinds, "
            "env_vars). See openbridge-mcp/CONTRACT.md for the canonical specification."
        ),
    )
    async def get_envelope_contract_tool() -> Dict[str, Any]:
        """Return the envelope contract metadata this server implements."""
        return {
            "contract_version": ENVELOPE_VERSION,
            "error_kinds": list(SUPPORTED_ERROR_KINDS),
            "normalized_kinds": [
                "renamed",
                "dropped_alias",
                "coerced",
                "unknown_field_passed_through",
            ],
            "env_vars": {
                "MCP_SCHEMA_KEY_NORMALIZATION_ENABLED": "default true; master switch for pre-flight key normalization",
                "MCP_SCHEMA_KEY_NORMALIZATION_META": "default false; emit `_meta.normalized` events on responses",
            },
            "spec_url": (
                "https://github.com/openbridge/openbridge-mcp/blob/main/CONTRACT.md"
            ),
        }


async def register_all_builtin_tools(
    server: FastMCP,
    mounted_servers: Optional[Dict[str, FastMCP]] = None,
    group_tool_counts: Optional[Dict[str, int]] = None,
    skip_tool_groups: bool = False,
):
    """Register all built-in tools with the server.

    :param server: FastMCP server instance.
    :param mounted_servers: Optional map of prefix -> sub-server for tool groups.
    :param group_tool_counts: Pre-counted total tools per group (including disabled).
    :param skip_tool_groups: If True, skip registering list_tool_groups/enable_tool_group.
        Used when code mode is active (GetTags replaces progressive disclosure).
    """
    # Register common tools that work for all auth types
    await register_envelope_contract_tools(server)
    await register_profile_tools(server)
    await register_profile_listing_tools(server)
    await register_region_tools(server)
    # Routing tools removed - override functionality was redundant
    await register_download_tools(server)
    await register_report_catalog_tools(server)
    await register_sampling_tools(server)
    # Cache & diagnostic tools removed - not core operations

    # Register auth-specific tools based on provider type
    auth_mgr = get_auth_manager()
    if auth_mgr and auth_mgr.provider:
        # Check provider_type property (not auth_method attribute)
        if hasattr(auth_mgr.provider, "provider_type"):
            if auth_mgr.provider.provider_type == "direct":
                # Direct OAuth authentication tools
                await register_oauth_tools_builtin(server)
                logger.info("Registered OAuth authentication tools")
            elif auth_mgr.provider.provider_type == "openbridge":
                # OpenBridge identity management tools
                await register_identity_tools(server)
                logger.info("Registered OpenBridge identity tools")

    # Register tool group tools for progressive disclosure
    # Skipped when code mode is active (GetTags serves the same browsing purpose)
    if mounted_servers and not skip_tool_groups:
        await register_tool_group_tools(
            server, mounted_servers, group_tool_counts=group_tool_counts
        )

    logger.info("Registered all built-in tools")
