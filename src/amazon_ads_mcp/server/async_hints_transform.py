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
    # AdsAPI v1 Reporting — the v1 endpoint uses a different ID space AND
    # a different field-name namespace than legacy v2/v3 reporting. The hint
    # text for AdsApiv1CreateReport is **conditionally built** at read time
    # based on settings.enable_report_fields_tool (see get_hint_text below).
    # We keep a placeholder entry here so _maybe_enrich still matches the
    # pattern; the placeholder text is never used directly.
    "AdsApiv1CreateReport": (
        "_PLACEHOLDER_",
        "AdsApiv1RetrieveReport",
    ),
    "AdsApiv1RetrieveReport": (
        "Returns the current status of an AdsAPI v1 report (PENDING, "
        "PROCESSING, COMPLETED, FAILED). PENDING and PROCESSING are both "
        "in-progress states. Typical completion is 1-5 minutes for small "
        "reports (≤1M rows) and up to 20 minutes for wide catalogs. Poll at "
        "30-60s intervals; do not retry creation. If not yet complete, tell "
        "the user a ballpark wait and suggest checking back shortly rather "
        "than polling in a loop. When COMPLETED, the response includes a "
        "download URL. Use `download_export` to persist the file to "
        "profile-scoped storage.",
        None,
    ),
}


# ---------- conditional hint assembly ------------------------------------


# Minimum-viable v1 CreateReport request body. Derived directly from the
# bundled spec (``dist/openapi/resources/AdsAPIv1All.json``) —
# CreateReportRequest → ReportCreate → CreateReportingQuery →
# CreateFilter/CreateComparisonPredicate. Locked by
# tests/unit/test_async_hints_report_fields.py::
# test_hint_skeleton_validates_against_openapi_create_report_request;
# when the spec regenerates, that test surfaces drift before this hint
# ships a broken example to clients.
#
# Non-obvious required fields the skeleton MUST carry:
#   • accessRequestedAccounts[].advertiserAccountId
#   • reports[].format, reports[].periods, reports[].query (all required)
#   • periods[].datePeriod (oneOf only option; clients miss the nesting)
#   • ComparisonPredicate.{comparisonOperator, field, not, values} ALL required
#     — ComparisonOperator.enum is ["EQUALS", "IN"] (not "EQUAL_TO")
#     — omitting ``not`` is a very common 400 source
_V1_CREATE_REPORT_SKELETON = (
    "Minimum viable request body (derived from AdsApiv1CreateReport schema):\n"
    "  {\n"
    '    "accessRequestedAccounts": [\n'
    '      {"advertiserAccountId": "<amzn1.ads-account.g.*>"}\n'
    "    ],\n"
    '    "reports": [\n'
    "      {\n"
    '        "format": "GZIP_JSON",\n'
    '        "periods": [\n'
    '          {"datePeriod": {"startDate": "2026-01-01",'
    ' "endDate": "2026-01-07"}}\n'
    "        ],\n"
    '        "query": {\n'
    '          "fields": ["campaign.id", "metric.totalCost"],\n'
    '          "filter": {\n'
    '            "and": {\n'
    '              "filters": [\n'
    '                {"on": {\n'
    '                    "field": "adProduct.value",\n'
    '                    "comparisonOperator": "EQUALS",\n'
    '                    "not": false,\n'
    '                    "values": ["SPONSORED_PRODUCTS"]\n'
    "                }}\n"
    "              ]\n"
    "            }\n"
    "          }\n"
    "        }\n"
    "      }\n"
    "    ]\n"
    "  }"
)


# Discoverability callout for the "true campaign state" follow-up question that
# naturally arises when the agent sees deliveryStatus in a report row (P1.6).
# Framed generically (category, not op IDs) + examples + always-available
# discovery fallback, so the hint degrades gracefully across deployments with
# different tool-mount configs or code-mode settings.
_V1_CAMPAIGN_STATE_CALLOUT = (
    "Note: v1 reports only return campaigns that served in-window. "
    "`deliveryStatus` from these reports is not a reliable proxy for true "
    "state (enabled/paused/archived) — paused campaigns simply won't appear. "
    "For a true campaign inventory, use the campaign list/query tools for "
    "the relevant product line (e.g. ADSP, Sponsored Brands, Sponsored "
    "Products, Sponsored Display). If the tool you need isn't visible, call "
    "`list_tool_groups` / `enable_tool_group` (always available). If code "
    "mode is enabled, you can also call `search` and `get_schemas` to "
    "locate the campaign-management surface."
)


_ADS_V1_CREATE_BASELINE = (
    "This is the AdsAPI v1 report creation endpoint (asynchronous). "
    "IMPORTANT:\n"
    "• `accessRequestedAccounts[].advertiserAccountId` must be the "
    "`amzn1.ads-account.g.*` account ID — NOT a legacy numeric profile "
    "ID. Use `allv1_QueryAdvertiserAccount` to resolve a "
    "profileId to its advertiserAccountId first.\n"
    "• Field names vary by endpoint and can reject guessed values. "
    "Use `list_report_fields` with "
    "`operation='allv1_AdsApiv1CreateReport'` for the validated "
    "field catalog before constructing `query.fields`.\n"
    "• `query.fields` must contain exactly one time dimension (e.g. "
    "`date.value`), at least one level-of-detail dimension (e.g. "
    "`campaign.id`), and at least one metric (e.g. `metric.clicks`).\n"
    "• To filter on ad product use `adProduct.value` "
    "(not `sponsoredProducts.adProduct`).\n\n"
    f"{_V1_CREATE_REPORT_SKELETON}\n\n"
    f"{_V1_CAMPAIGN_STATE_CALLOUT}\n\n"
    "Returns a reportId; poll with `allv1_AdsApiv1RetrieveReport`. "
    "Typical completion: 1-20 minutes."
)

_ADS_V1_CREATE_REPORT_FIELDS = (
    "This is the AdsAPI v1 report creation endpoint (asynchronous). "
    "IMPORTANT:\n"
    "• `accessRequestedAccounts[].advertiserAccountId` must be the "
    "`amzn1.ads-account.g.*` account ID — NOT a legacy numeric profile "
    "ID. Use `allv1_QueryAdvertiserAccount` to resolve a "
    "profileId to its advertiserAccountId first.\n"
    "• BEFORE CreateReport, validate your field list with:\n"
    '    report_fields(mode="validate", operation="allv1_AdsApiv1CreateReport",\n'
    '                  validate_fields=["metric.clicks", "campaign.id"])\n'
    "  Returns unknown_fields, missing_required, incompatible_pairs so you\n"
    "  never submit a field that will 400.\n"
    "• TO DISCOVER fields, use:\n"
    '    report_fields(mode="query", category="metric", search="click")\n'
    "  or `list_report_fields(operation='allv1_AdsApiv1CreateReport')` for\n"
    "  the minimal empirical baseline.\n"
    "• `query.fields` must contain exactly one time dimension (e.g. "
    "`date.value`), at least one level-of-detail dimension (e.g. "
    "`campaign.id`), and at least one metric (e.g. `metric.clicks`).\n"
    "• To filter on ad product use `adProduct.value` "
    "(not `sponsoredProducts.adProduct`).\n\n"
    f"{_V1_CREATE_REPORT_SKELETON}\n\n"
    f"{_V1_CAMPAIGN_STATE_CALLOUT}\n\n"
    "Returns a reportId; poll with `allv1_AdsApiv1RetrieveReport`. "
    "Typical completion: 1-20 minutes."
)


def get_hint_text(pattern: str) -> str:
    """Return the rendered hint text for *pattern*, applying settings gates.

    Only the AdsApiv1CreateReport hint varies at read time. All other
    hints are returned verbatim from ASYNC_OPERATION_HINTS.
    """
    if pattern == "AdsApiv1CreateReport":
        from ..config.settings import settings

        return (
            _ADS_V1_CREATE_REPORT_FIELDS
            if settings.enable_report_fields_tool
            else _ADS_V1_CREATE_BASELINE
        )
    text, _ = ASYNC_OPERATION_HINTS[pattern]
    return text


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
        for pattern, (_placeholder, _status_tool) in ASYNC_OPERATION_HINTS.items():
            if tool.name.endswith(pattern):
                current_desc = tool.description or ""
                if "asynchronous" in current_desc.lower():
                    # Already has async guidance, skip
                    return tool
                hint = get_hint_text(pattern)
                enriched_desc = f"{current_desc}\n\n{hint}".strip()
                self._enriched_count += 1
                return tool.model_copy(update={"description": enriched_desc})
        return tool
