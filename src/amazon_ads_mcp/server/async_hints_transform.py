"""Transform that enriches async API tools with polling hints.

Many Amazon Ads API operations are asynchronous — reports, exports, AMC
workflows, and audience jobs return an ID and require polling for completion.
This transform appends guidance to those tool descriptions so the LLM
communicates wait times to the user rather than spinning in a polling loop.
"""

import logging
from collections.abc import Sequence
from typing import Dict, Optional, Tuple

from fastmcp.server.transforms import Transform
from fastmcp.tools.tool import Tool

logger = logging.getLogger(__name__)

# Maps (tool_name_pattern) -> (hint_text, status_tool_hint)
# Patterns are matched against the end of the tool name (after namespace prefix)
ASYNC_OPERATION_HINTS: Dict[str, Tuple[str, Optional[str]]] = {
    # V3 Reporting
    "createAsyncReport": (
        "This operation is asynchronous. It returns a reportId immediately. "
        "The report may take 1-20 minutes to generate depending on the date "
        "range and complexity. Tell the user the reportId and estimated wait "
        "time. Use getAsyncReport to check status — do not poll repeatedly. "
        "When status is COMPLETED, use download_export to save the file.",
        "getAsyncReport",
    ),
    "getAsyncReport": (
        "Returns the current status of an async report (PENDING, PROCESSING, "
        "COMPLETED, or FAILED). If not yet complete, tell the user and suggest "
        "checking back shortly rather than polling in a loop. When COMPLETED, "
        "the response includes a temporary download URL (pre-signed, expires "
        "in minutes). Present this URL to the user so they can download the "
        "file directly if they wish. Also use download_export to save a copy "
        "to the server for later access via /downloads.",
        None,
    ),
    # Exports
    "CampaignExport": (
        "This creates an asynchronous campaign export. It returns an exportId "
        "immediately. Exports typically complete within 1-5 minutes. Tell the "
        "user the exportId and suggest checking status shortly. Use GetExport "
        "to check status. When COMPLETED, use download_export to save the file.",
        "GetExport",
    ),
    "AdGroupExport": (
        "This creates an asynchronous ad group export. It returns an exportId "
        "immediately. Exports typically complete within 1-5 minutes. Tell the "
        "user the exportId and suggest checking status shortly. Use GetExport "
        "to check status. When COMPLETED, use download_export to save the file.",
        "GetExport",
    ),
    "AdExport": (
        "This creates an asynchronous ad export. It returns an exportId "
        "immediately. Exports typically complete within 1-5 minutes. Tell the "
        "user the exportId and suggest checking status shortly. Use GetExport "
        "to check status. When COMPLETED, use download_export to save the file.",
        "GetExport",
    ),
    "TargetExport": (
        "This creates an asynchronous target export. It returns an exportId "
        "immediately. Exports typically complete within 1-5 minutes. Tell the "
        "user the exportId and suggest checking status shortly. Use GetExport "
        "to check status. When COMPLETED, use download_export to save the file.",
        "GetExport",
    ),
    "GetExport": (
        "Returns the current status of an export (PROCESSING, COMPLETED, or "
        "FAILED). If not yet complete, tell the user and suggest checking back "
        "shortly rather than polling in a loop. When COMPLETED, the response "
        "includes a temporary download URL (pre-signed, expires in minutes). "
        "Present this URL to the user so they can download the file directly "
        "if they wish. Also use download_export to save a copy to the server "
        "for later access via /downloads.",
        None,
    ),
    # AMC Workflows
    "createWorkflowExecution": (
        "This creates an asynchronous AMC workflow execution. It returns a "
        "workflowExecutionId immediately. AMC queries can take 5-30 minutes "
        "depending on data volume. Tell the user the execution ID and expected "
        "wait time. Use getWorkflowExecution to check status. When SUCCEEDED, "
        "use getWorkflowExecutionDownloadUrls to get result URLs.",
        "getWorkflowExecution",
    ),
    "getWorkflowExecution": (
        "Returns the current status of an AMC workflow execution (PENDING, "
        "RUNNING, SUCCEEDED, FAILED, or CANCELLED). If not yet complete, tell "
        "the user and suggest checking back rather than polling in a loop. "
        "When SUCCEEDED, use getWorkflowExecutionDownloadUrls to get result "
        "URLs and present them to the user.",
        None,
    ),
    "getWorkflowExecutionDownloadUrls": (
        "Returns pre-signed S3 download URLs for completed AMC workflow "
        "results. These URLs are temporary and expire in minutes. Present "
        "the URLs to the user so they can download the results directly. "
        "Also use download_export to save copies to the server for later "
        "access via /downloads.",
        None,
    ),
    # AMC Audiences
    "ManageAudienceV2": (
        "This creates an asynchronous audience management job. It returns a "
        "jobRequestId immediately. Use ManageAudienceStatusV2 to check status. "
        "Tell the user the job ID and suggest checking back shortly.",
        "ManageAudienceStatusV2",
    ),
    "createQueryBasedAudience": (
        "This creates an asynchronous query-based audience. It returns an "
        "audienceExecutionId immediately. Audience creation can take several "
        "minutes. Tell the user the execution ID and suggest checking status "
        "shortly with getQueryBasedAudienceByAudienceExecutionId.",
        "getQueryBasedAudienceByAudienceExecutionId",
    ),
    # MMM Reports
    "createMmmReport": (
        "This creates an asynchronous Marketing Mix Modeling report. It returns "
        "a reportId immediately. MMM reports can take several minutes. Tell the "
        "user the report ID and suggest checking status with getMmmReport.",
        "getMmmReport",
    ),
    "getMmmReport": (
        "Returns the current status of an MMM report. If not yet complete, "
        "tell the user and suggest checking back rather than polling in a loop. "
        "When complete, present the download URL to the user so they can "
        "download the file directly. Also use download_export to save a copy "
        "to the server.",
        None,
    ),
    # Brand Metrics
    "generateBrandMetricsReport": (
        "This creates an asynchronous Brand Metrics report. It returns a "
        "reportId immediately. Tell the user the report ID and suggest checking "
        "status with getBrandMetricsReport.",
        "getBrandMetricsReport",
    ),
    "getBrandMetricsReport": (
        "Returns the current status of a Brand Metrics report. If not yet "
        "complete, tell the user and suggest checking back rather than polling. "
        "When complete, present the download URL to the user so they can "
        "download the file directly. Also use download_export to save a copy "
        "to the server.",
        None,
    ),
    # Creative Assets Batch
    "assetsBatchRegister": (
        "This creates an asynchronous batch registration request. It returns a "
        "requestId immediately. Use getAssetsBatchRegister to check status.",
        "getAssetsBatchRegister",
    ),
}


class AsyncHintsTransform(Transform):
    """Enriches async API tool descriptions with polling guidance.

    This transform appends behavioral hints to tools that trigger
    long-running operations, guiding the LLM to communicate wait
    times to users rather than entering polling loops.
    """

    def __init__(self) -> None:
        self._enriched_count = 0

    async def list_tools(self, tools: Sequence[Tool]) -> Sequence[Tool]:
        """Enrich tool descriptions with async operation hints."""
        result = []
        for tool in tools:
            enriched = self._maybe_enrich(tool)
            result.append(enriched)
        if self._enriched_count:
            logger.info(
                "AsyncHintsTransform: enriched %d tool descriptions with "
                "polling guidance",
                self._enriched_count,
            )
        return result

    async def get_tool(self, name, call_next, *, version=None):
        """Enrich a single tool lookup with async hints."""
        tool = await call_next(name, version=version)
        if tool is None:
            return None
        return self._maybe_enrich(tool)

    def _maybe_enrich(self, tool: Tool) -> Tool:
        """Append async hint to tool description if it matches a known pattern."""
        for pattern, (hint, _status_tool) in ASYNC_OPERATION_HINTS.items():
            if tool.name.endswith(pattern):
                current_desc = tool.description or ""
                if "asynchronous" in current_desc.lower():
                    # Already has async guidance, skip
                    return tool
                enriched_desc = f"{current_desc}\n\n{hint}".strip()
                self._enriched_count += 1
                return tool.model_copy(update={"description": enriched_desc})
        return tool
