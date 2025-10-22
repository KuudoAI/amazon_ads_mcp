"""Export and report download handler for Amazon Ads API.

This module provides functionality for downloading and storing Amazon Ads API
exports and reports in a structured local directory hierarchy.

Key Features:
    - Organized file storage with timestamped naming
    - Support for multiple export types (campaigns, adgroups, ads, targets)
    - Metadata storage alongside downloaded files
    - Automatic file extension detection
    - Resource type-based directory organization

Directory Structure:
    data/
    ├── exports/
    │   ├── campaigns/
    │   ├── adgroups/
    │   ├── ads/
    │   └── targets/
    ├── reports/
    │   ├── brandmetrics/
    │   └── general/
    └── downloads/
        └── general/

Dependencies:
    - httpx: Async HTTP client for downloads
    - pathlib: Path manipulation
    - asyncio: Asynchronous operations

Environment Variables:
    - AMAZON_ADS_DOWNLOAD_DIR: Custom download directory path
"""

import gzip
import json
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

# S3 downloads use plain httpx client, not authenticated client

logger = logging.getLogger(__name__)


class ExportDownloadHandler:
    """Handles downloading and storing Amazon Ads API exports and reports.

    This class provides a comprehensive solution for managing export downloads
    with organized storage, metadata tracking, and automatic file organization.

    Downloads are organized in a hierarchical structure:
        data/<resource_type>/<sub_type>/<timestamp>_<filename>

    Examples:
        - data/exports/campaigns/20250108_153045_campaign_export.csv
        - data/reports/brandmetrics/20250108_160000_brand_lift_report.json
        - data/exports/adgroups/20250108_170000_adgroup_export.csv

    The handler automatically:
        - Creates directory structures as needed
        - Generates timestamped filenames
        - Detects file extensions from content-type headers
        - Stores metadata alongside downloaded files
        - Organizes files by resource type and subtype

    :param base_dir: Base directory for all downloads (default: ./data)
    :type base_dir: Path | None
    """

    def __init__(self, base_dir: Path = None):
        """Initialize the download handler.

        Creates the base directory structure and initializes the handler
        for managing export downloads.

        :param base_dir: Base directory for downloads (default: ./data)
        :type base_dir: Path | None
        """
        self.base_dir = base_dir or Path.cwd() / "data"
        self.base_dir.mkdir(exist_ok=True)
        self.client_initialized = False
        logger.info(
            f"Download handler initialized with base directory: {self.base_dir}"
        )

    def get_resource_path(self, url: str, export_type: str | None = None) -> Path:
        """Determine the resource path from URL and export type.

        Analyzes the URL structure to determine the appropriate directory
        for storing the downloaded file. Creates the directory structure
        if it doesn't exist.

        :param url: The URL being accessed
        :type url: str
        :param export_type: Optional explicit export type (campaign, adgroup, etc.)
        :type export_type: str | None
        :return: Path object for the resource directory
        :rtype: Path
        """
        parsed = urlparse(url)
        path_parts = parsed.path.strip("/").split("/")

        # Check for S3 offline report storage
        # Validate hostname is legitimate AWS domain
        hostname = (parsed.hostname or "").lower()
        is_aws_domain = hostname.endswith(".amazonaws.com") or hostname == "amazonaws.com"
        if hostname and is_aws_domain:
            if any(
                pattern in hostname
                for pattern in [
                    "offline-report-storage",
                    "report-storage",
                    "s3",
                ]
            ):
                resource_type = "reports"
                sub_type = "s3-reports"
            else:
                resource_type = "downloads"
                sub_type = "s3"
        # Determine resource type from path
        elif "exports" in path_parts:
            resource_type = "exports"
            # Try to determine sub-type from export_type or URL
            if export_type:
                sub_type = export_type.lower()
            else:
                # Default sub-types based on common patterns
                sub_type = "general"
        elif "reports" in path_parts:
            resource_type = "reports"
            # Extract report type if available
            idx = path_parts.index("reports")
            if idx + 1 < len(path_parts):
                sub_type = path_parts[idx + 1].lower()
            else:
                sub_type = "general"
        # Check filename patterns in path
        elif parsed.path and any(
            pattern in parsed.path.lower() for pattern in ["report-", ".json.gz"]
        ):
            resource_type = "reports"
            sub_type = "async"
        elif "brandMetrics" in parsed.path:
            resource_type = "reports"
            sub_type = "brandmetrics"
        # Use export_type hint if provided
        elif export_type:
            if export_type.lower() in ["report", "reports"]:
                resource_type = "reports"
                sub_type = export_type.lower()
            elif export_type.lower() in ["export", "exports"]:
                resource_type = "exports"
                sub_type = export_type.lower()
            else:
                resource_type = "downloads"
                sub_type = export_type.lower()
        else:
            # Generic download
            resource_type = "downloads"
            sub_type = path_parts[0] if path_parts else "general"

        # Create the directory structure
        resource_path = self.base_dir / resource_type / sub_type
        resource_path.mkdir(parents=True, exist_ok=True)

        return resource_path

    def _infer_filename_and_type(
        self,
        url: str,
        content_disposition: str | None,
        content_type: str | None,
        export_id: str,
    ) -> tuple[str, bool]:
        """Infer filename and whether content is gzipped.

        :param url: The download URL
        :param content_disposition: Content-Disposition header value
        :param content_type: Content-Type header value
        :param export_id: Export ID for fallback naming
        :return: tuple of (filename, is_gzipped)
        """
        # Try Content-Disposition first
        if content_disposition and "filename=" in content_disposition:
            match = re.search(r'filename="?([^\"]+)"?', content_disposition)
            if match:
                filename = match.group(1)
                is_gzipped = (
                    filename.endswith(".gz") or "gzip" in (content_type or "").lower()
                )
                return filename, is_gzipped

        # Try to get filename from URL
        parsed = urlparse(url)
        path_parts = parsed.path.rstrip("/").split("/")
        if path_parts and path_parts[-1]:
            filename = path_parts[-1]
            # Check if it looks like a filename (has extension)
            if "." in filename:
                is_gzipped = (
                    filename.endswith(".gz") or "gzip" in (content_type or "").lower()
                )
                return filename, is_gzipped

        # Fall back to content-type based extension
        is_gzipped = False
        if content_type:
            content_type_lower = content_type.lower()
            if "gzip" in content_type_lower or "x-gzip" in content_type_lower:
                extension = ".json.gz"  # Assume JSON inside gzip
                is_gzipped = True
            elif "json" in content_type_lower:
                extension = ".json"
            elif "xml" in content_type_lower:
                extension = ".xml"
            elif "csv" in content_type_lower:
                extension = ".csv"
            elif "parquet" in content_type_lower:
                extension = ".parquet"
            elif "octet-stream" in content_type_lower:
                # For binary/octet-stream, try to infer from URL
                if ".json.gz" in url:
                    extension = ".json.gz"
                    is_gzipped = True
                elif ".csv.gz" in url:
                    extension = ".csv.gz"
                    is_gzipped = True
                elif ".gz" in url:
                    extension = ".gz"
                    is_gzipped = True
                else:
                    extension = ".bin"
            else:
                extension = ".bin"  # Binary/unknown
        else:
            # No content-type, try URL
            if ".json.gz" in url:
                extension = ".json.gz"
                is_gzipped = True
            elif ".gz" in url:
                extension = ".gz"
                is_gzipped = True
            else:
                extension = ".bin"

        # Generate filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        # Truncate export_id if too long
        clean_id = export_id[:8] if len(export_id) > 8 else export_id
        filename = f"{timestamp}_export_{clean_id}{extension}"

        return filename, is_gzipped

    def generate_filename(
        self,
        original_name: str | None = None,
        export_id: str | None = None,
        extension: str = ".csv",
    ) -> str:
        """Generate a timestamped filename.

        Creates a unique filename with timestamp prefix for organizing
        downloaded files chronologically.

        :param original_name: Original filename if available
        :type original_name: str | None
        :param export_id: Export ID to include in filename
        :type export_id: str | None
        :param extension: File extension (default: .csv)
        :type extension: str
        :return: Timestamped filename
        :rtype: str
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        if original_name:
            # Clean the original name
            name = Path(original_name).stem
            ext = Path(original_name).suffix or extension
            return f"{timestamp}_{name}{ext}"
        elif export_id:
            # Use export ID in filename
            # Truncate if too long
            clean_id = export_id[:20] if len(export_id) > 20 else export_id
            return f"{timestamp}_export_{clean_id}{extension}"
        else:
            return f"{timestamp}_download{extension}"

    async def download_export(
        self,
        export_url: str,
        export_id: str,
        export_type: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Path:
        """Download an export file and store it locally.

        Downloads an export file from the provided URL and stores it in the
        appropriate local directory structure. Automatically detects file
        extensions and creates metadata files.

        :param export_url: URL to download the export from
        :type export_url: str
        :param export_id: Export ID for identification
        :type export_id: str
        :param export_type: Type of export (campaign, adgroup, etc.)
        :type export_type: str | None
        :param metadata: Optional metadata to store alongside the file
        :type metadata: dict[str, Any] | None
        :return: Path to the downloaded file
        :rtype: Path
        :raises httpx.HTTPStatusError: When download fails
        :raises Exception: When file operations fail
        """
        # Determine where to save
        resource_path = self.get_resource_path(export_url, export_type)

        # Use plain httpx client for S3 URLs (they don't need auth headers)
        async with httpx.AsyncClient(timeout=httpx.Timeout(60.0)) as client:
            response = await client.get(export_url)
        response.raise_for_status()

        # Determine filename and gzip state
        cd = response.headers.get("content-disposition")
        ct = response.headers.get("content-type")
        filename, is_gzipped = self._infer_filename_and_type(
            export_url, cd, ct, export_id
        )

        # Paths
        file_path = resource_path / filename
        final_path = file_path

        # Save original bytes
        content_bytes = response.content
        with open(file_path, "wb") as f:
            f.write(content_bytes)

        # If gzipped, also decompress to base (without .gz)
        if is_gzipped and filename.endswith(".gz"):
            try:
                decompressed = gzip.decompress(content_bytes)
                base_name = filename[:-3]  # strip .gz
                decompressed_path = resource_path / base_name
                with open(decompressed_path, "wb") as out:
                    out.write(decompressed)
                final_path = decompressed_path
                logger.info(
                    f"Downloaded and decompressed export to: {final_path} (original: {file_path})"
                )
            except Exception as e:
                logger.warning(
                    f"Failed to decompress gzip content, keeping original: {e}"
                )
        else:
            logger.info(f"Downloaded export to: {final_path}")

        # Save metadata if provided
        if metadata:
            meta_path = final_path.with_suffix(".meta.json")
            metadata = dict(metadata)  # shallow copy to avoid side effects
            metadata["download_timestamp"] = datetime.now().isoformat()
            metadata["export_id"] = export_id
            metadata["export_type"] = export_type
            metadata["original_url"] = export_url
            metadata["file_size"] = len(content_bytes)
            metadata["original_filename"] = filename
            metadata["content_type"] = ct
            metadata["gzipped"] = is_gzipped
            metadata["saved_path"] = str(final_path)

            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump(metadata, f, indent=2)
            logger.debug(f"Saved metadata to: {meta_path}")

        return final_path

    async def handle_export_response(
        self,
        export_response: dict[str, Any],
        export_type: str | None = None,
    ) -> Path | None:
        """Handle an export response, downloading if ready.

        Processes an export response from the Amazon Ads API and automatically
        downloads the file if the export is completed. Handles various export
        statuses appropriately.

        :param export_response: Response from GetExport API
        :type export_response: dict[str, Any]
        :param export_type: Type of export for organization
        :type export_type: str | None
        :return: Path to downloaded file if successful, None if not ready
        :rtype: Path | None
        """
        status = export_response.get("status", "UNKNOWN")
        export_id = export_response.get("exportId", "unknown")

        if status == "COMPLETED":
            url = export_response.get("url")
            if url:
                # Download the export
                try:
                    file_path = await self.download_export(
                        export_url=url,
                        export_id=export_id,
                        export_type=export_type,
                        metadata=export_response,
                    )
                    return file_path
                except Exception as e:
                    logger.error(f"Failed to download export {export_id}: {e}")
                    return None
            else:
                logger.warning(f"Export {export_id} completed but no URL provided")
                return None
        elif status == "PROCESSING":
            logger.info(f"Export {export_id} is still processing")
            return None
        elif status == "FAILED":
            error = export_response.get("error", {})
            logger.error(f"Export {export_id} failed: {error}")
            return None
        else:
            logger.warning(f"Export {export_id} has unknown status: {status}")
            return None

    def list_downloads(self, resource_type: str | None = None) -> dict[str, list]:
        """List all downloaded files.

        Scans the download directory structure and returns information about
        all downloaded files, optionally filtered by resource type.

        :param resource_type: Optional filter by resource type
        :type resource_type: str | None
        :return: Dictionary mapping resource paths to file lists
        :rtype: dict[str, list]
        """
        downloads = {}

        if resource_type:
            search_paths = [self.base_dir / resource_type]
        else:
            search_paths = [p for p in self.base_dir.iterdir() if p.is_dir()]

        for resource_dir in search_paths:
            if not resource_dir.exists():
                continue

            for sub_dir in resource_dir.iterdir():
                if sub_dir.is_dir():
                    files = []
                    for file_path in sub_dir.iterdir():
                        if file_path.is_file() and not file_path.name.endswith(
                            ".meta.json"
                        ):
                            # Get file info
                            stat = file_path.stat()
                            files.append(
                                {
                                    "name": file_path.name,
                                    "path": str(file_path),
                                    "size": stat.st_size,
                                    "modified": datetime.fromtimestamp(
                                        stat.st_mtime
                                    ).isoformat(),
                                    "has_metadata": file_path.with_suffix(
                                        ".meta.json"
                                    ).exists(),
                                }
                            )

                    if files:
                        relative_path = sub_dir.relative_to(self.base_dir)
                        downloads[str(relative_path)] = files

        return downloads


# Global handler instance
_download_handler: ExportDownloadHandler | None = None


def get_download_handler(
    base_dir: Path | None = None,
) -> ExportDownloadHandler:
    """Get or create the global download handler.

    Provides a singleton instance of ExportDownloadHandler for consistent
    download management across the application. Respects environment
    variable configuration.

    :param base_dir: Base directory for downloads
    :type base_dir: Path | None
    :return: ExportDownloadHandler instance
    :rtype: ExportDownloadHandler
    """
    global _download_handler
    if _download_handler is None:
        # Use environment variable if set, otherwise use provided dir or default
        import os

        env_dir = os.environ.get("AMAZON_ADS_DOWNLOAD_DIR")
        if env_dir:
            base_dir = Path(env_dir)
        elif base_dir is None:
            base_dir = Path.cwd() / "data"

        _download_handler = ExportDownloadHandler(base_dir)
    return _download_handler
