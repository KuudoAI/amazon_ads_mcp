"""Built-in prompts for Amazon Ads MCP Server.

These prompts provide structured templates for common Amazon Ads API workflows,
helping LLMs generate correct sequences of tool calls and handle typical tasks.
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fastmcp import FastMCP


async def register_all_builtin_prompts(server: "FastMCP") -> None:
    """Register all built-in prompts with the server.

    Args:
        server: The FastMCP server instance to register prompts with
    """

    # Authentication and Profile Setup
    @server.prompt(
        name="auth_profile_setup",
        description="Complete authentication and profile setup for Amazon Ads API",
        tags={"auth", "profile", "setup"},
        meta={"version": "0.1", "owner": "ads-platform"},
    )
    def auth_profile_setup_prompt(region: str = "na") -> str:
        """Guide authentication, region selection, and profile setup."""
        return (
            "Goal: Set up Amazon Ads API authentication and select an active profile.\n"
            "Steps for the model:\n"
            "1) Start OAuth flow if needed:\n"
            "   - Tool: start_oauth_flow\n"
            "   - Monitor with: check_oauth_status\n"
            "2) Set the region:\n"
            f"   - Tool: set_active_region (use '{region}')\n"
            "3) Discover available profiles safely:\n"
            "   - Tool: summarize_profiles\n"
            "   - Optional: search_profiles or page_profiles to locate a specific profile\n"
            "   - Note: acprof:GET /v2/profiles can return very large payloads\n"
            "4) Set the active profile:\n"
            "   - Tool: set_active_profile\n"
            "   - Use the profileId from the previous step\n"
            "5) Verify setup:\n"
            "   - Tool: get_routing_state\n"
            "   - Tool: get_active_profile\n"
            "   - Tool: check_oauth_status\n"
            "Return: Summary of authentication status, active region, and selected profile."
        )

    # Export and Download Workflow
    @server.prompt(
        name="export_entity_download",
        description="Request entity export, poll status, and download when ready",
        tags={"exports", "download", "reports"},
        meta={"version": "0.1", "owner": "ads-platform"},
    )
    def export_entity_download_prompt(
        entity: str,
        profile_id: str | None = None,
        date_range: str = "last_30_days",
        state_filter: str | None = None,
    ) -> str:
        """Export Amazon Ads entities and download the results."""
        profile_note = (
            f" (use profileId: {profile_id})"
            if profile_id
            else " (use current active profile)"
        )
        filter_note = f", stateFilter: '{state_filter}'" if state_filter else ""

        return (
            f"Goal: Export and download Amazon Ads {entity} data.\n"
            "Steps for the model:\n"
            "1) Verify region and profile:\n"
            "   - Tool: get_routing_state\n"
            "   - Tool: get_active_profile\n"
            "2) Create export request:\n"
            f"   - Tool: export:POST /{entity}/export\n"
            f"   - Body: {{profileId{profile_note}, dateRange: '{date_range}'{filter_note}}}\n"
            "3) Extract exportId from response and poll status:\n"
            "   - Tool: export:GET /exports/{{exportId}}\n"
            "   - Repeat every 5-10 seconds until status is COMPLETED or FAILED\n"
            "   - Check for 'downloadLocation' in response\n"
            "4) When COMPLETED with downloadLocation:\n"
            "   - Tool: download_export\n"
            "   - Parameters: exportId and export_url from step 3\n"
            "5) Return the local file_path and summary of exported data.\n"
            "Error handling: If 401/403, check authentication and profile access rights."
        )

    # Campaign Creation
    @server.prompt(
        name="create_campaign",
        description="Create a new advertising campaign with proper validation",
        tags={"campaign", "creation", "sponsored"},
        meta={"version": "0.1", "owner": "ads-platform"},
    )
    def create_campaign_prompt(
        campaign_type: str = "sponsoredProducts",
        objective: str = "SALES",
        name: str = "New Campaign",
        budget: float = 100.0,
        marketplace_id: str | None = None,
    ) -> str:
        """Create a new campaign with specified parameters."""
        mp_note = f", marketplaceId: '{marketplace_id}'" if marketplace_id else ""

        return (
            f"Goal: Create a new {campaign_type} campaign.\n"
            "Steps for the model:\n"
            "1) Verify authentication and profile:\n"
            "   - Tool: get_active_profile\n"
            "   - Tool: check_oauth_status\n"
            "2) Create the campaign:\n"
            "   - Tool: cm:POST /adsApi/v1/create/campaigns\n"
            "   - Body structure:\n"
            "     {{\n"
            f"       channel: '{campaign_type}',\n"
            f"       objective: '{objective}',\n"
            f"       name: '{name}',\n"
            f"       budget: {budget},\n"
            "       budgetType: 'DAILY',\n"
            "       state: 'ENABLED',\n"
            "       startDate: <today's date in YYYYMMDD format>,\n"
            f"       targetingType: 'MANUAL'{mp_note}\n"
            "     }}\n"
            "3) Verify campaign creation:\n"
            "   - Tool: cm:POST /adsApi/v1/query/campaigns\n"
            "   - Body: {{filters: {{campaignNameFilter: {{name: '{name}'}}}}}}\n"
            "4) Return the campaign ID and confirmation details.\n"
            "Note: Ensure all required fields are included based on campaign type."
        )

    # Error Recovery
    @server.prompt(
        name="troubleshoot_api_error",
        description="Diagnose and recover from common API errors",
        tags={"error", "troubleshooting", "recovery"},
        meta={"version": "0.1", "owner": "ads-platform"},
    )
    def troubleshoot_api_error_prompt(
        error_code: int,
        error_message: str | None = None,
        last_operation: str | None = None,
    ) -> str:
        """Guide error diagnosis and recovery steps."""
        context = f" during '{last_operation}'" if last_operation else ""
        msg_note = f": {error_message}" if error_message else ""

        recovery_steps = {
            401: (
                "Authentication issue detected. Steps:\n"
                "1) Check token status: check_oauth_status\n"
                "2) If expired, refresh: refresh_oauth_token\n"
                "3) If refresh fails, restart: start_oauth_flow\n"
                "4) Retry the original operation"
            ),
            403: (
                "Access denied. Steps:\n"
                "1) Verify active profile: get_active_profile\n"
                "2) Check profile permissions: acprof:GET /v2/profiles\n"
                "3) Verify region/marketplace: get_routing_state\n"
                "4) Switch profile if needed: set_active_profile\n"
                "5) Retry with correct profile"
            ),
            404: (
                "Resource not found. Steps:\n"
                "1) Verify the resource ID is correct\n"
                "2) Check if using correct region: get_routing_state\n"
                "3) List available resources to confirm existence\n"
                "4) Update parameters and retry"
            ),
            429: (
                "Rate limit exceeded. Steps:\n"
                "1) Wait 60 seconds before retrying\n"
                "2) Implement exponential backoff for subsequent retries\n"
                "3) Consider reducing request frequency"
            ),
        }

        steps = recovery_steps.get(
            error_code,
            (
                "Unknown error. Generic steps:\n"
                "1) Check authentication: check_oauth_status\n"
                "2) Verify routing: get_routing_state\n"
                "3) Review request parameters\n"
                "4) Check API documentation for requirements"
            ),
        )

        return (
            f"Goal: Diagnose and recover from error {error_code}{msg_note}{context}.\n"
            f"{steps}\n"
            "Additional diagnostics:\n"
            "- Review the full error response for details\n"
            "- Check if the API endpoint requires specific scopes\n"
            "- Verify request body format and required fields\n"
            "Return: Root cause analysis and whether the issue was resolved."
        )

    # Async Report Generation
    @server.prompt(
        name="generate_async_report",
        description="Create and retrieve an async report with polling",
        tags={"reports", "async", "analytics"},
        meta={"version": "0.1", "owner": "ads-platform"},
    )
    def generate_async_report_prompt(
        report_type: str = "campaigns",
        metrics: str = "impressions,clicks,spend,sales",
        time_period: str = "LAST_30_DAYS",
        group_by: str | None = None,
    ) -> str:
        """Generate async report and retrieve results."""
        grouping = f", groupBy: ['{group_by}']" if group_by else ""

        return (
            f"Goal: Generate and retrieve a {report_type} performance report.\n"
            "Steps for the model:\n"
            "1) Create report request:\n"
            "   - Tool: rpasyn:POST /reporting/reports\n"
            "   - Body structure:\n"
            "     {{\n"
            f"       reportType: '{report_type.upper()}',\n"
            "       metrics: ["
            + ", ".join(f'"{m}"' for m in metrics.split(","))
            + "],\n"
            f"       timeUnit: 'DAILY',\n"
            f"       timePeriod: '{time_period}'{grouping}\n"
            "     }}\n"
            "2) Extract reportId and poll status:\n"
            "   - Tool: rpasyn:GET /reporting/reports/{{reportId}}\n"
            "   - Check 'status' field (PENDING → IN_PROGRESS → SUCCESS/FAILURE)\n"
            "   - Poll every 5-10 seconds\n"
            "3) When SUCCESS, extract download URL:\n"
            "   - Look for 'url' or 'location' in response\n"
            "   - Tool: download_export with the URL\n"
            "4) Return the downloaded file path and report metadata.\n"
            "Note: Large reports may take several minutes to generate."
        )

    # Region Setup
    @server.prompt(
        name="setup_region",
        description="Configure region for API routing",
        tags={"region", "routing"},
        meta={"version": "0.2", "owner": "ads-platform"},
    )
    def setup_region_prompt(
        target_region: str,
    ) -> str:
        """Set up region configuration."""
        return (
            f"Goal: Configure API routing for region '{target_region}'.\n"
            "Steps for the model:\n"
            f"1) Set the target region:\n"
            f"   - Tool: set_active_region\n"
            f"   - Parameter: region = '{target_region}'\n"
            f"   - Valid regions: na, eu, fe\n"
            f"2) Verify configuration:\n"
            "   - Tool: get_routing_state\n"
            "   - Confirm region is correctly set\n"
            f"3) Test with a simple API call:\n"
            "   - Tool: acprof:GET /v2/profiles\n"
            "   - Verify profiles are from the correct region\n"
            "Return: Current routing configuration and validation results."
        )
