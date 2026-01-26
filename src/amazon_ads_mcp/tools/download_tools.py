"""Download management tools for Amazon Ads MCP server.

This module provides tools for managing downloads of exports and reports
from the Amazon Ads API. It handles export status checking, file
downloading, local file management, and cleanup operations.

The tools integrate with the export download handler to provide a
unified interface for managing downloaded data files.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional

from ..utils.export_download_handler import get_download_handler

logger = logging.getLogger(__name__)


async def check_and_download_export(
    export_id: str,
    export_response: Dict[str, Any],
    export_type: Optional[str] = None,
    profile_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Check export status and download if ready.

    This function checks the status of an export and attempts to download
    it if it's ready. It can infer the export type from the export ID
    if not provided, and handles various export statuses appropriately.

    :param export_id: The export ID to check and download
    :type export_id: str
    :param export_response: Response from the GetExport API call
    :type export_response: Dict[str, Any]
    :param export_type: Optional export type (campaign, adgroup, etc.)
    :type export_type: Optional[str]
    :param profile_id: Optional profile ID for scoped storage
    :type profile_id: Optional[str]
    :return: Dictionary containing status and download information
    :rtype: Dict[str, Any]
    """
    handler = get_download_handler()

    # Infer export type from response if not provided
    if not export_type and export_id:
        # Try to decode from export ID
        import base64

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
        except (AttributeError, TypeError, ValueError, KeyError):
            export_type = "general"

    # Handle the export response with profile scoping
    file_path = await handler.handle_export_response(
        export_response, export_type, profile_id=profile_id
    )

    if file_path:
        return {
            "success": True,
            "status": "downloaded",
            "file_path": str(file_path),
            "export_id": export_id,
            "message": f"Export downloaded successfully to {file_path}",
        }
    else:
        status = export_response.get("status", "UNKNOWN")
        if status == "PROCESSING":
            return {
                "success": False,
                "status": "processing",
                "export_id": export_id,
                "message": "Export is still being processed. Check again later.",
            }
        elif status == "FAILED":
            error = export_response.get("error", {})
            return {
                "success": False,
                "status": "failed",
                "export_id": export_id,
                "error": error,
                "message": f"Export failed: {error.get('message', 'Unknown error')}",
            }
        else:
            return {
                "success": False,
                "status": status.lower(),
                "export_id": export_id,
                "message": f"Export has status {status} - no download available",
            }


async def list_downloaded_files(
    resource_type: Optional[str] = None,
    profile_id: Optional[str] = None,
) -> Dict[str, Any]:
    """List all downloaded files in the data directory.

    Scans the data directory for downloaded files and provides a summary
    of all available downloads. Can filter by resource type to show only
    specific types of downloads.

    When profile_id is provided:
        - Lists files only from data/profiles/{profile_id}/

    When profile_id is None:
        - Lists files only from legacy (non-profile) directories

    :param resource_type: Optional filter to show only specific resource types
    :type resource_type: Optional[str]
    :param profile_id: Optional profile ID for scoped listing
    :type profile_id: Optional[str]
    :return: Dictionary containing download summary and file listings
    :rtype: Dict[str, Any]
    """
    handler = get_download_handler()
    # handler.list_downloads returns a flat list of file dicts
    files = handler.list_downloads(resource_type, profile_id=profile_id)

    # Calculate totals from the flat list
    total_files = len(files)
    total_size = sum(f.get("size", 0) for f in files)

    return {
        "base_directory": str(handler.base_dir),
        "total_files": total_files,
        "total_size_bytes": total_size,
        "files": files,  # Flat list format
    }


async def get_download_metadata(file_path: str) -> Dict[str, Any]:
    """Get metadata for a downloaded file.

    Retrieves metadata associated with a downloaded file, including
    any custom metadata stored alongside the file. Falls back to
    basic file information if no metadata is available.

    :param file_path: Path to the downloaded file
    :type file_path: str
    :return: Dictionary containing file metadata and status
    :rtype: Dict[str, Any]
    """
    path = Path(file_path)

    if not path.exists():
        return {
            "success": False,
            "error": "File not found",
            "file_path": file_path,
        }

    meta_path = path.with_suffix(".meta.json")

    if meta_path.exists():
        with open(meta_path) as f:
            metadata = json.load(f)
        return {"success": True, "file_path": file_path, "metadata": metadata}
    else:
        # Return basic file info
        stat = path.stat()
        return {
            "success": True,
            "file_path": file_path,
            "metadata": {
                "file_name": path.name,
                "file_size": stat.st_size,
                "modified": stat.st_mtime,
                "note": "No detailed metadata available",
            },
        }


async def clean_old_downloads(
    resource_type: Optional[str] = None, days_old: int = 7
) -> Dict[str, Any]:
    """Clean up old downloaded files.

    Removes downloaded files that are older than the specified number
    of days. This helps manage disk space by cleaning up outdated
    export data. Can filter by resource type to clean only specific
    types of downloads.

    :param resource_type: Optional filter by resource type
    :type resource_type: Optional[str]
    :param days_old: Delete files older than this many days
    :type days_old: int
    :return: Dictionary containing cleanup summary and deleted file list
    :rtype: Dict[str, Any]
    """
    from datetime import datetime, timedelta

    handler = get_download_handler()
    cutoff_date = datetime.now() - timedelta(days=days_old)

    deleted_files = []
    deleted_size = 0

    if resource_type:
        search_paths = [handler.base_dir / resource_type]
    else:
        search_paths = [p for p in handler.base_dir.iterdir() if p.is_dir()]

    for resource_dir in search_paths:
        if not resource_dir.exists():
            continue

        for sub_dir in resource_dir.iterdir():
            if sub_dir.is_dir():
                for file_path in sub_dir.iterdir():
                    if file_path.is_file():
                        stat = file_path.stat()
                        modified = datetime.fromtimestamp(stat.st_mtime)

                        if modified < cutoff_date:
                            deleted_size += stat.st_size
                            deleted_files.append(str(file_path))

                            # Delete the file and its metadata
                            file_path.unlink()
                            meta_path = file_path.with_suffix(".meta.json")
                            if meta_path.exists():
                                meta_path.unlink()

    return {
        "success": True,
        "deleted_files": len(deleted_files),
        "deleted_size_bytes": deleted_size,
        "files": deleted_files,
        "message": f"Deleted {len(deleted_files)} files older than {days_old} days",
    }
