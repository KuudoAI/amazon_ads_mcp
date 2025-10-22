"""
Download/Export content-type resolver for Amazon Ads API.

This module provides helpers to determine preferred Accept/Content-Type
for known download-like flows across Amazon Ads APIs, beyond classic
Exports (e.g., DSP Measurement results, Sponsored Ads report/snapshot
redirectors, Brand Metrics report retrieval).
"""

import base64
import logging
from typing import List, Optional

logger = logging.getLogger(__name__)


def resolve_export_content_type(export_id: str) -> Optional[str]:
    """
    Resolve the correct content-type for an export based on its ID.

    Amazon export IDs appear to be base64-encoded with a suffix indicating type:
    - ,C = Campaign export
    - ,A = Ad Group export
    - ,AD = Ads export
    - ,T = Targets export

    :param export_id: The export ID from Amazon
    :type export_id: str
    :return: The appropriate content-type or None if unable to determine
    :rtype: Optional[str]
    """
    if not export_id:
        return None

    try:
        # Export IDs appear to be base64 encoded with a type suffix
        # Example: "OTc2MDhjNmEtNDg3Zi00YzMyLTllOWEtMDMwNjNhYTk1MGM0LEM"
        # Decodes to: "97608c6a-487f-4c32-9e9a-03063aa950c4,C"

        # Try to decode to check for pattern
        try:
            # Add padding if needed for base64 decode
            padded = export_id + "=" * (4 - len(export_id) % 4)
            decoded = base64.b64decode(padded).decode("utf-8")
            if "," in decoded:
                _, suffix = decoded.rsplit(",", 1)
                suffix = suffix.upper()

                # Map suffix to content-type
                suffix_map = {
                    "C": "application/vnd.campaignsexport.v1+json",
                    "A": "application/vnd.adgroupsexport.v1+json",
                    "AD": "application/vnd.adsexport.v1+json",
                    "T": "application/vnd.targetsexport.v1+json",
                }

                content_type = suffix_map.get(suffix)
                if content_type:
                    logger.debug(
                        f"Resolved export type from ID suffix '{suffix}': {content_type}"
                    )
                    return content_type
        except Exception:
            # Not base64 or doesn't match expected pattern
            pass

        # Fallback: check if the ID itself contains hints
        export_id_lower = export_id.lower()

        if "campaign" in export_id_lower:
            return "application/vnd.campaignsexport.v1+json"
        elif "adgroup" in export_id_lower:
            return "application/vnd.adgroupsexport.v1+json"
        elif "ad" in export_id_lower and "adgroup" not in export_id_lower:
            return "application/vnd.adsexport.v1+json"
        elif "target" in export_id_lower:
            return "application/vnd.targetsexport.v1+json"

    except Exception as e:
        logger.warning(f"Error resolving export content-type: {e}")

    return None


def get_export_accept_headers(export_id: str) -> List[str]:
    """
    Get a prioritized list of Accept headers for an export.

    If we can determine the type, return that first.
    Otherwise return all possibilities in a sensible order.

    :param export_id: The export ID
    :type export_id: str
    :return: List of content-types to try
    :rtype: List[str]
    """
    # Try to resolve the specific type
    specific_type = resolve_export_content_type(export_id)

    # All possible types
    all_types = [
        "application/vnd.campaignsexport.v1+json",
        "application/vnd.adgroupsexport.v1+json",
        "application/vnd.adsexport.v1+json",
        "application/vnd.targetsexport.v1+json",
    ]

    if specific_type and specific_type in all_types:
        # Put the specific type first, then other vendor types, then application/json
        # FastMCP's experimental parser needs application/json in the Accept list
        all_types.remove(specific_type)
        return [specific_type] + all_types + ["application/json"]

    # Include application/json as fallback for FastMCP compatibility
    return all_types + ["application/json"]


def get_measurement_accept_headers(prefer_csv: bool = False) -> List[str]:
    """
    Preferred Accept headers for DSP Measurement result downloads.

    Measurement endpoints support both JSON and CSV vendor types, with a 307
    redirect to an S3 location for actual file download. If CSV is preferred,
    return CSV first; otherwise JSON first.
    """
    json_type = "application/vnd.measurementresult.v1.2+json"
    csv_type = "text/vnd.measurementresult.v1.2+csv"
    # Include application/json for FastMCP compatibility
    types = [csv_type, json_type] if prefer_csv else [json_type, csv_type]
    return types + ["application/json"]


def get_brandmetrics_accept_headers() -> List[str]:
    """
    Preferred Accept headers for Brand Metrics report endpoints.

    Brand Metrics typically returns vendor JSON, with multiple versions
    (v1.1 and v1). Prefer the latest first.
    """
    return [
        "application/vnd.insightsbrandmetrics.v1.1+json",
        "application/vnd.insightsbrandmetrics.v1+json",
        "application/json",  # Include for FastMCP compatibility
    ]


def get_reports_download_accept_headers() -> List[str]:
    """
    Sponsored Ads reports/snapshots download endpoints return a 307 redirect
    with location header. Accept is usually application/json for the status
    envelope prior to redirect.
    """
    return ["application/json"]


def resolve_download_accept_headers(
    method: str, url: str, *, prefer_csv: bool = False
) -> List[str]:
    """
    Resolve Accept headers for known download endpoints using URL heuristics.

    - Exports: use export-specific vendor types inferred from export_id where possible.
    - DSP Measurement: support JSON/CSV vendor types (prefer CSV if requested).
    - Sponsored Ads Reports/Snapshots: default to application/json (redirect flow).
    - Brand Metrics: prefer v1.1 then v1 vendor JSON.
    - S3 URLs: No Accept override (let S3 handle it)
    """
    m = (method or "GET").upper()
    u = (url or "").lower()

    # Don't override Accept for S3 URLs - they serve pre-defined content
    from urllib.parse import urlparse

    parsed = urlparse(url)
    # Validate hostname is legitimate AWS domain
    hostname = (parsed.hostname or "").lower()
    is_aws_domain = hostname.endswith(".amazonaws.com") or hostname == "amazonaws.com"
    if hostname and is_aws_domain:
        # S3 URLs don't need Accept headers - they serve what they have
        return []

    # Export creation endpoints (POST)
    if m == "POST" and "/export" in u:
        if "/campaigns/export" in u:
            return [
                "application/vnd.campaignsexport.v1+json",
                "application/json",
            ]
        elif "/adgroups/export" in u:
            return [
                "application/vnd.adgroupsexport.v1+json",
                "application/json",
            ]
        elif "/ads/export" in u:
            return ["application/vnd.adsexport.v1+json", "application/json"]
        elif "/targets/export" in u:
            return [
                "application/vnd.targetsexport.v1+json",
                "application/json",
            ]

    # Export retrieval pattern: /exports/{exportId}
    if "/exports/" in u:
        # Try to extract exportId and leverage export content-type map
        try:
            import re

            match = re.search(r"/exports/([^/?]+)", url)
            if match:
                export_id = match.group(1)
                return get_export_accept_headers(export_id)
        except Exception:
            pass
        return get_export_accept_headers("")

    # DSP Measurement results (audienceResearch/brandLift/creativeTesting/etc.)
    if "/dsp/measurement/" in u or "/measurement/" in u:
        return get_measurement_accept_headers(prefer_csv=prefer_csv)

    # Sponsored Display/Snapshots/Reports download endpoints
    if "/snapshots/" in u and "/download" in u:
        return get_reports_download_accept_headers()
    if "/v2/reports/" in u and "/download" in u:
        return get_reports_download_accept_headers()

    # Brand Metrics
    if "/insights/brandmetrics/" in u or "brandmetrics" in u:
        return get_brandmetrics_accept_headers()

    # Default fallback
    return ["application/json"]
