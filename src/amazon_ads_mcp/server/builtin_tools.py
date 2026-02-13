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
from ..models.builtin_responses import (
    AsyncReportResponse,
    ClearProfileResponse,
    DownloadedFile,
    DownloadExportResponse,
    EnableToolGroupResponse,
    GetDownloadUrlResponse,
    GetProfileResponse,
    GetRegionResponse,
    ListDownloadsResponse,
    ListRegionsResponse,
    ProfileSelectorResponse,
    ProfilePageResponse,
    ProfileCacheRefreshResponse,
    ProfileSearchResponse,
    ProfileSummaryResponse,
    RoutingStateResponse,
    SamplingTestResponse,
    SetProfileResponse,
    SetRegionResponse,
    ToolGroupInfo,
    ToolGroupsResponse,
)
from ..tools import identity, profile, profile_listing, region
from ..tools.oauth import OAuthTools

# Removed http_client imports - override functions were removed

logger = logging.getLogger(__name__)


async def register_identity_tools(server: FastMCP):
    """Register identity management tools.

    :param server: FastMCP server instance.
    """

    @server.tool(
        name="set_active_identity",
        description="Set the active identity for Amazon Ads API calls",
    )
    async def set_active_identity_tool(
        ctx: Context,
        identity_id: str,
        persist: bool = False,
    ):
        """Set the active identity for API calls."""
        from ..models import SetActiveIdentityRequest

        req = SetActiveIdentityRequest(
            identity_id=identity_id,
            persist=persist,
        )
        return await identity.set_active_identity(req)

    @server.tool(
        name="get_active_identity",
        description="Get the currently active identity",
    )
    async def get_active_identity_tool(ctx: Context):
        """Get the currently active identity."""
        return await identity.get_active_identity()

    @server.tool(name="list_identities", description="List all available identities")
    async def list_identities_tool(ctx: Context) -> dict:
        """List all available identities."""
        return await identity.list_identities()


async def register_profile_tools(server: FastMCP):
    """Register profile management tools.

    :param server: FastMCP server instance.
    """

    @server.tool(
        name="set_active_profile",
        description="Set the active profile ID for API calls",
    )
    async def set_active_profile_tool(
        ctx: Context, profile_id: str
    ) -> SetProfileResponse:
        """Set the active profile ID."""
        result = await profile.set_active_profile(profile_id)
        return SetProfileResponse(**result)

    @server.tool(
        name="get_active_profile",
        description="Get the currently active profile ID",
    )
    async def get_active_profile_tool(ctx: Context) -> GetProfileResponse:
        """Get the currently active profile ID."""
        result = await profile.get_active_profile()
        return GetProfileResponse(**result)

    @server.tool(name="clear_active_profile", description="Clear the active profile ID")
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
        description="Summarize available profiles by country and account type",
    )
    async def summarize_profiles_tool(ctx: Context) -> ProfileSummaryResponse:
        """Summarize available profiles."""
        result = await profile_listing.summarize_profiles()
        return ProfileSummaryResponse(**result)

    @server.tool(
        name="search_profiles",
        description="Search profiles by name, country, or account type",
    )
    async def search_profiles_tool(
        ctx: Context,
        query: Optional[str] = None,
        country_code: Optional[str] = None,
        account_type: Optional[str] = None,
        limit: int = profile_listing.DEFAULT_SEARCH_LIMIT,
    ) -> ProfileSearchResponse:
        """Search profiles with bounded output."""
        result = await profile_listing.search_profiles(
            query=query,
            country_code=country_code,
            account_type=account_type,
            limit=limit,
        )
        return ProfileSearchResponse(**result)

    @server.tool(
        name="page_profiles",
        description="Page through profiles with offset and limit",
    )
    async def page_profiles_tool(
        ctx: Context,
        country_code: Optional[str] = None,
        account_type: Optional[str] = None,
        offset: int = 0,
        limit: int = profile_listing.DEFAULT_PAGE_LIMIT,
    ) -> ProfilePageResponse:
        """Return a page of profiles with bounded output."""
        result = await profile_listing.page_profiles(
            country_code=country_code,
            account_type=account_type,
            offset=offset,
            limit=limit,
        )
        return ProfilePageResponse(**result)

    @server.tool(
        name="refresh_profiles_cache",
        description="Force refresh of cached profiles for the current identity and region",
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
        description="Set the region for Amazon Ads API calls",
    )
    async def set_region_tool(ctx: Context, region_code: str) -> SetRegionResponse:
        """Set the region for API calls."""
        result = await region.set_region(region_code)
        return SetRegionResponse(**result)

    @server.tool(name="get_region", description="Get the current region setting")
    async def get_region_tool(ctx: Context) -> GetRegionResponse:
        """Get the current region."""
        result = await region.get_region()
        return GetRegionResponse(**result)

    @server.tool(name="list_regions", description="List all available regions")
    async def list_regions_tool(ctx: Context) -> ListRegionsResponse:
        """List available regions."""
        result = await region.list_regions()
        return ListRegionsResponse(**result)

    @server.tool(
        name="get_routing_state",
        description="Get the current routing state including region, host, and headers",
    )
    async def get_routing_state_tool(ctx: Context) -> RoutingStateResponse:
        """Get the complete routing state for debugging."""
        from ..utils.http_client import get_routing_state
        from ..utils.region_config import RegionConfig

        result = get_routing_state()

        # Provide defaults when no routing state has been established yet
        # (e.g., on a fresh server before any requests)
        current_region = settings.amazon_ads_region or "na"
        default_host = RegionConfig.get_api_host(current_region)

        # Apply sandbox host replacement (same pattern used in http_client.py)
        if settings.amazon_ads_sandbox_mode:
            default_host = default_host.replace("advertising-api", "advertising-api-test")

        return RoutingStateResponse(
            region=result.get("region", current_region),
            host=result.get("host", default_host),
            headers=result.get("headers", {}),
            sandbox=settings.amazon_ads_sandbox_mode,
        )


# Removed region_identity_tools - list_identities_by_region was just a convenience wrapper


# Routing override tools removed - use the main region/marketplace tools instead


async def register_download_tools(server: FastMCP):
    """Register download management tools.

    :param server: FastMCP server instance
    :type server: FastMCP
    """

    # Background task with progress reporting for long-running downloads
    # task=True enables MCP background task protocol (SEP-1686) in FastMCP 2.14+
    @server.tool(
        name="download_export",
        description="Download a completed export to local storage (supports background execution)",
        task=True,  # Enable background task execution
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
        file_path: str,
    ) -> GetDownloadUrlResponse:
        """Generate the download URL for a file.

        :param ctx: MCP context
        :param file_path: Relative path from list_downloads output
        :return: Response with download URL
        """
        from pathlib import Path
        from urllib.parse import quote

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

        # Validate file exists
        from ..utils.export_download_handler import get_download_handler

        handler = get_download_handler()
        profile_dir = handler.base_dir / "profiles" / profile_id
        full_path = profile_dir / file_path

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
            quote(part, safe="") for part in Path(file_path).parts
        )

        download_url = f"{base_url}/downloads/{encoded_path}"
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


async def register_reporting_tools(server: FastMCP):
    """Register reporting workflow tools with background task support.

    These wrapper tools orchestrate the full report workflow (request → poll → download)
    with progress tracking. OpenAPI-generated tools cannot have task=True, so we
    create builtin wrappers for long-running operations.

    :param server: FastMCP server instance
    :type server: FastMCP
    """

    @server.tool(
        name="request_async_report",
        description="Request and download an async report with progress tracking (V3 Reporting API)",
        task=True,  # Enable background task execution
    )
    async def request_async_report_tool(
        ctx: Context,
        report_type: str,
        start_date: str,
        end_date: str,
        time_unit: str = "DAILY",
        group_by: Optional[str] = None,
        columns: Optional[str] = None,
        filters: Optional[str] = None,
        poll_interval_seconds: int = 10,
        max_poll_attempts: int = 60,
        progress: Progress = Progress(),
    ) -> AsyncReportResponse:
        """Request an async report and wait for completion with progress tracking.

        This tool handles the full V3 Reporting API workflow:
        1. Creates a report request
        2. Polls for completion with progress updates
        3. Downloads the completed report
        4. Returns the local file path

        Supports background execution - clients can track progress while report
        generates in the background.

        :param report_type: Report type (e.g., spCampaigns, spTargeting, sbCampaigns)
        :param start_date: Report start date (YYYY-MM-DD)
        :param end_date: Report end date (YYYY-MM-DD)
        :param time_unit: Time granularity (DAILY, SUMMARY)
        :param group_by: Comma-separated list of dimensions to group by
        :param columns: Comma-separated list of columns to include
        :param filters: JSON string of filters to apply
        :param poll_interval_seconds: Seconds between status checks (default: 10)
        :param max_poll_attempts: Maximum polling attempts before timeout (default: 60)
        :return: Report result with file path
        """
        import asyncio
        import json as json_module

        from ..utils.http_client import get_authenticated_client

        # Total steps: create (1) + poll (variable) + download (1)
        await progress.set_total(max_poll_attempts + 2)
        await progress.set_message("Creating report request...")
        await progress.increment()

        # Get HTTP client for API calls
        client = await get_authenticated_client()

        # Build report request body
        report_config = {
            "reportType": report_type,
            "startDate": start_date,
            "endDate": end_date,
            "timeUnit": time_unit,
            "format": "GZIP_JSON",
        }

        if group_by:
            report_config["groupBy"] = [g.strip() for g in group_by.split(",")]
        if columns:
            report_config["columns"] = [c.strip() for c in columns.split(",")]
        if filters:
            try:
                report_config["filters"] = json_module.loads(filters)
            except json_module.JSONDecodeError:
                return AsyncReportResponse(
                    success=False, error="Invalid JSON in filters parameter"
                )

        # Create report request
        try:
            response = await client.post("/reporting/reports", json=report_config)
            response.raise_for_status()
            create_result = response.json()
            report_id = create_result.get("reportId")

            if not report_id:
                return AsyncReportResponse(
                    success=False, error="No reportId in response"
                )

        except Exception as e:
            return AsyncReportResponse(
                success=False, error=f"Failed to create report: {e}"
            )

        await progress.set_message(f"Report created: {report_id}")

        # Poll for completion
        download_url = None
        for attempt in range(max_poll_attempts):
            await progress.set_message(f"Checking status... (attempt {attempt + 1})")
            await progress.increment()

            try:
                status_response = await client.get(f"/reporting/reports/{report_id}")
                status_response.raise_for_status()
                status_data = status_response.json()

                status = status_data.get("status", "UNKNOWN")

                if status == "COMPLETED":
                    download_url = status_data.get("url")
                    break
                elif status == "FAILED":
                    error_details = status_data.get("failureReason", "Unknown error")
                    return AsyncReportResponse(
                        success=False,
                        report_id=report_id,
                        status=status,
                        error=f"Report failed: {error_details}",
                    )
                elif status in ("PENDING", "PROCESSING", "IN_PROGRESS"):
                    await asyncio.sleep(poll_interval_seconds)
                else:
                    await asyncio.sleep(poll_interval_seconds)

            except Exception as e:
                logger.warning(f"Error checking report status: {e}")
                await asyncio.sleep(poll_interval_seconds)

        if not download_url:
            return AsyncReportResponse(
                success=False,
                report_id=report_id,
                error=f"Report did not complete within {max_poll_attempts * poll_interval_seconds} seconds",
            )

        # Download the report
        await progress.set_message("Downloading report...")
        await progress.increment()

        try:
            from ..utils.export_download_handler import get_download_handler

            handler = get_download_handler()

            # Get active profile for scoped storage
            auth_mgr = get_auth_manager()
            profile_id = auth_mgr.get_active_profile_id() if auth_mgr else None

            file_path = await handler.download_export(
                export_url=download_url,
                export_id=report_id,
                export_type=f"report_{report_type}",
                metadata={"report_config": report_config},
                profile_id=profile_id,
            )

            await progress.set_message("Report download complete!")

            return AsyncReportResponse(
                success=True,
                report_id=report_id,
                report_type=report_type,
                file_path=str(file_path),
                message=f"Report downloaded to {file_path}",
            )

        except Exception as e:
            return AsyncReportResponse(
                success=False,
                report_id=report_id,
                error=f"Failed to download report: {e}",
                download_url=download_url,
            )

    logger.info("Registered reporting workflow tools with background task support")


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
    server: FastMCP, mounted_servers: Dict[str, list]
):
    """Register progressive tool disclosure tools.

    These tools let MCP clients discover and selectively enable API tool
    groups, keeping the initial ``tools/list`` response minimal.

    :param server: FastMCP server instance.
    :param mounted_servers: Map of prefix -> list of sub-servers for mounted groups.
    """

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
            count = 0
            active = 0
            for sub in sub_servers:
                tools = await sub.get_tools()
                count += len(tools)
                active += sum(1 for t in tools.values() if t.enabled)
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
            tools = await sub.get_tools()
            for tool in tools.values():
                if enable:
                    tool.enable()
                else:
                    tool.disable()
                tool_names.append(f"{prefix}_{tool.name}")
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


async def register_all_builtin_tools(
    server: FastMCP,
    mounted_servers: Optional[Dict[str, FastMCP]] = None,
):
    """Register all built-in tools with the server.

    :param server: FastMCP server instance.
    :param mounted_servers: Optional map of prefix -> sub-server for tool groups.
    """
    # Register common tools that work for all auth types
    await register_profile_tools(server)
    await register_profile_listing_tools(server)
    await register_region_tools(server)
    # Routing tools removed - override functionality was redundant
    await register_download_tools(server)
    await register_reporting_tools(server)
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
    if mounted_servers:
        await register_tool_group_tools(server, mounted_servers)

    logger.info("Registered all built-in tools")
