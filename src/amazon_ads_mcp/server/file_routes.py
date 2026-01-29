"""HTTP custom routes for file download operations.

These routes operate alongside the MCP endpoint to provide
actual file transfer capability that MCP cannot efficiently handle.

Architecture Pattern:
    - Control Plane (MCP): list_downloads, get_download_url tools
    - Data Plane (HTTP): GET /downloads/{path} for actual file bytes

Security:
    - Profile-scoped directories (multi-tenant isolation)
    - Path traversal prevention via resolve() + relative_to()
    - Sensitive file blocking
    - Configurable size limits and extension whitelist
    - Bearer token authentication (optional)
"""

import json
import logging
from pathlib import Path
from typing import Optional
from urllib.parse import quote

from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, Response

logger = logging.getLogger(__name__)

# Lazy import to avoid circular dependencies
settings = None


def _get_settings():
    """Lazy load settings to avoid import cycles."""
    global settings
    if settings is None:
        try:
            from ..config.settings import settings as _settings

            settings = _settings
        except ImportError:
            # Fallback to a mock settings object for testing
            class MockSettings:
                download_auth_token = None
                download_max_file_size = 512 * 1024 * 1024  # 512MB
                download_allowed_extensions = None

            settings = MockSettings()
    return settings


def get_auth_manager():
    """Get the auth manager instance."""
    try:
        from ..auth.manager import get_auth_manager as _get_auth_manager

        return _get_auth_manager()
    except ImportError:
        return None


def get_download_handler():
    """Get the export download handler instance."""
    try:
        from ..utils.export_download_handler import get_download_handler as _get_handler

        return _get_handler()
    except ImportError:
        return None


# =============================================================================
# Route Registration
# =============================================================================


def register_file_routes(server) -> None:
    """Register HTTP file routes with the FastMCP server.

    Args:
        server: FastMCP server instance
    """
    if not hasattr(server, "custom_route"):
        logger.warning(
            "Server does not support custom routes (stdio transport?). "
            "File download routes not registered."
        )
        return

    @server.custom_route("/downloads/{file_path:path}", methods=["GET"])
    async def download_file(request: Request) -> Response:
        """Download a file by its path.

        This endpoint serves files downloaded by export/report tools.
        Files are validated to be within the allowed download directory
        AND scoped to the current profile context.

        Path Parameters:
            file_path: The relative file path within downloads directory

        Returns:
            FileResponse with file content, or JSONResponse with error
        """
        file_path_str = request.path_params["file_path"]

        # 1. Authentication (if enabled)
        auth_error = await _verify_download_auth(request)
        if auth_error is not None:
            return auth_error

        # 2. Get current profile for tenant isolation
        profile_id = await _get_current_profile_id()
        if not profile_id:
            return _create_error_response(
                error="No active profile",
                error_code="NO_PROFILE",
                status_code=401,
                hint="Set active profile using set_active_profile before downloading",
            )

        # 3. Get profile-scoped base directory
        handler = get_download_handler()
        if not handler:
            return _create_error_response(
                error="Download handler not available",
                error_code="HANDLER_ERROR",
                status_code=500,
            )

        profile_dir = _get_profile_base_dir(handler, profile_id)

        # 4. Resolve and validate file path
        resolved_path = _resolve_file_path(file_path_str, profile_dir)
        if resolved_path is None:
            return _create_error_response(
                error="File not found",
                error_code="FILE_NOT_FOUND",
                status_code=404,
                file_path=file_path_str,
                hint="Use list_downloads to see available files",
            )

        # 5. Security validation
        security_error = _validate_file_access(resolved_path, profile_dir)
        if security_error:
            response = JSONResponse(security_error, status_code=403)
            return _add_cors_headers(response)

        # 6. Serve file
        logger.info(f"Serving file: {resolved_path} for profile: {profile_id}")
        response = FileResponse(
            path=resolved_path,
            filename=resolved_path.name,
            media_type=_get_media_type(resolved_path),
        )
        return _add_cors_headers(response)

    @server.custom_route("/downloads", methods=["GET"])
    async def list_download_files(request: Request) -> JSONResponse:
        """List available downloads with their download URLs.

        Query Parameters:
            type: Optional filter by export type (campaigns, reports, etc.)

        Returns:
            JSONResponse with list of files and their download URLs
        """
        auth_error = await _verify_download_auth(request)
        if auth_error is not None:
            return auth_error

        # Get current profile for tenant isolation
        profile_id = await _get_current_profile_id()
        if not profile_id:
            return _create_error_response(
                error="No active profile",
                error_code="NO_PROFILE",
                status_code=401,
                hint="Set active profile before listing files",
            )

        handler = get_download_handler()
        if not handler:
            return _create_error_response(
                error="Download handler not available",
                error_code="HANDLER_ERROR",
                status_code=500,
            )

        profile_dir = _get_profile_base_dir(handler, profile_id)
        export_type = request.query_params.get("type")

        files = []
        base_url = _get_base_url(request)

        if not profile_dir.exists():
            response = JSONResponse(
                {"files": [], "count": 0, "profile_id": profile_id}
            )
            return _add_cors_headers(response)

        for file_path in profile_dir.rglob("*"):
            if file_path.is_file() and not file_path.name.endswith(".meta.json"):
                relative_path = file_path.relative_to(profile_dir)

                # Filter by type if specified
                if export_type and export_type not in str(relative_path):
                    continue

                # URL-encode path segments for special characters
                encoded_path = "/".join(
                    quote(part, safe="") for part in relative_path.parts
                )

                file_info = {
                    "name": file_path.name,
                    "path": str(relative_path),
                    "size_bytes": file_path.stat().st_size,
                    "download_url": f"{base_url}/downloads/{encoded_path}",
                }

                # Include metadata if available
                meta_path = Path(str(file_path) + ".meta.json")
                if meta_path.exists():
                    try:
                        with open(meta_path) as f:
                            file_info["metadata"] = json.load(f)
                    except (json.JSONDecodeError, IOError):
                        pass

                files.append(file_info)

        response = JSONResponse(
            {
                "files": files,
                "count": len(files),
                "profile_id": profile_id,
            }
        )
        return _add_cors_headers(response)

    @server.custom_route("/downloads", methods=["OPTIONS"])
    async def downloads_cors_preflight_root(request: Request) -> Response:
        """Handle CORS preflight for /downloads."""
        response = Response(status_code=204)
        return _add_cors_headers(response)

    @server.custom_route("/downloads/{file_path:path}", methods=["OPTIONS"])
    async def downloads_cors_preflight_path(request: Request) -> Response:
        """Handle CORS preflight for /downloads/{path}."""
        response = Response(status_code=204)
        return _add_cors_headers(response)

    logger.info("Registered file download routes at /downloads")


# =============================================================================
# Helper Functions
# =============================================================================


async def _get_current_profile_id() -> Optional[str]:
    """Get the current profile ID from auth context.

    Returns:
        Profile ID string or None if not available
    """
    auth_mgr = get_auth_manager()
    if auth_mgr:
        return auth_mgr.get_active_profile_id()
    return None


def _get_profile_base_dir(handler, profile_id: str) -> Path:
    """Get profile-scoped base directory.

    Directory structure:
    data/
    ├── profiles/
    │   ├── <profile_id_1>/
    │   │   ├── exports/
    │   │   │   └── campaigns/
    │   │   └── reports/
    │   │       └── async/
    │   └── <profile_id_2>/
    │       └── ...

    Args:
        handler: ExportDownloadHandler instance
        profile_id: Current profile ID

    Returns:
        Path to profile-scoped directory

    Raises:
        ValueError: If profile_id is empty or None
    """
    if not profile_id:
        raise ValueError("Profile ID required for file access")

    profile_dir = handler.base_dir / "profiles" / profile_id
    profile_dir.mkdir(parents=True, exist_ok=True)
    return profile_dir


def _resolve_file_path(file_id: str, base_dir: Path) -> Optional[Path]:
    """Resolve a file ID to an actual path.

    Supports:
    - Direct relative paths: "exports/campaigns/report.json"
    - Export IDs: Look up in metadata files

    Args:
        file_id: File identifier or relative path
        base_dir: Base directory to search within

    Returns:
        Resolved Path or None if not found
    """
    # Try as direct path first
    direct_path = base_dir / file_id
    if direct_path.exists() and direct_path.is_file():
        return direct_path

    # Look up by export_id in metadata files
    for meta_file in base_dir.rglob("*.meta.json"):
        try:
            with open(meta_file) as f:
                meta = json.load(f)
            if meta.get("export_id") == file_id:
                # Data file is the meta file path without .meta.json
                data_file_name = meta_file.name.replace(".meta.json", "")
                data_file = meta_file.parent / data_file_name
                if data_file.exists():
                    return data_file
        except (json.JSONDecodeError, IOError):
            continue

    return None


def _validate_file_access(file_path: Path, base_dir: Path) -> Optional[dict]:
    """Validate that file access is allowed.

    Security checks:
    1. Path traversal prevention (symlink-aware)
    2. File within allowed directory
    3. Not a sensitive file type
    4. File size within limits
    5. Extension whitelist (if configured)

    Args:
        file_path: Path to validate
        base_dir: Allowed base directory

    Returns:
        None if access allowed, error dict otherwise
    """
    # 1. Path traversal prevention
    try:
        resolved = file_path.resolve()
        base_resolved = base_dir.resolve()
        resolved.relative_to(base_resolved)
    except ValueError:
        return {
            "error": "Access denied: path traversal detected",
            "error_code": "PATH_TRAVERSAL",
            "allowed_directory": str(base_dir),
        }

    # 2. Block sensitive files
    sensitive_patterns = [
        ".env",
        "credentials",
        "secret",
        ".key",
        ".pem",
        ".p12",
        "token",
        "password",
        "private",
    ]
    if any(pattern in file_path.name.lower() for pattern in sensitive_patterns):
        return {
            "error": "Access denied: sensitive file type",
            "error_code": "SENSITIVE_FILE",
        }

    # 3. File size enforcement
    cfg = _get_settings()
    file_size = file_path.stat().st_size
    max_size = cfg.download_max_file_size
    if file_size > max_size:
        return {
            "error": f"File too large: {file_size} bytes exceeds {max_size} bytes",
            "error_code": "FILE_TOO_LARGE",
            "file_size": file_size,
            "max_size": max_size,
            "hint": "Contact administrator to increase DOWNLOAD_MAX_FILE_SIZE",
        }

    # 4. Extension whitelist (if configured)
    allowed_ext_str = cfg.download_allowed_extensions
    if allowed_ext_str:
        allowed_extensions = {
            ext.strip().lower() for ext in allowed_ext_str.split(",") if ext.strip()
        }
        file_ext = file_path.suffix.lower()
        if file_ext not in allowed_extensions:
            return {
                "error": f"File type not allowed: {file_ext}",
                "error_code": "EXTENSION_NOT_ALLOWED",
                "allowed_extensions": list(allowed_extensions),
            }

    return None


def _get_media_type(file_path: Path) -> str:
    """Determine MIME type from file extension.

    Args:
        file_path: Path to get media type for

    Returns:
        MIME type string
    """
    extension_map = {
        ".json": "application/json",
        ".csv": "text/csv",
        ".tsv": "text/tab-separated-values",
        ".txt": "text/plain",
        ".xml": "application/xml",
        ".gz": "application/gzip",
        ".zip": "application/zip",
        ".jsonl": "application/x-ndjson",
    }
    return extension_map.get(file_path.suffix.lower(), "application/octet-stream")


async def _verify_download_auth(request: Request) -> Optional[JSONResponse]:
    """Verify download authentication via Bearer token.

    Args:
        request: Starlette request object

    Returns:
        None if auth succeeds or is disabled
        JSONResponse with 401 if auth fails
    """
    cfg = _get_settings()
    # Settings now loads from AMAZON_ADS_DOWNLOAD_AUTH_TOKEN or DOWNLOAD_AUTH_TOKEN
    auth_token = cfg.download_auth_token

    if not auth_token:
        # Auth disabled - allow access
        return None

    # Check Authorization header
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        provided_token = auth_header.split(" ", 1)[1]
        if provided_token == auth_token:
            return None  # Auth success

    response = JSONResponse(
        {
            "error": "Unauthorized",
            "error_code": "UNAUTHORIZED",
            "hint": "Provide Authorization: Bearer <token> header",
        },
        status_code=401,
    )
    return _add_cors_headers(response)


def _get_base_url(request: Request) -> str:
    """Get the correct base URL, respecting proxy headers.

    Handles X-Forwarded-Proto and X-Forwarded-Host from reverse proxies.

    Args:
        request: Starlette request object

    Returns:
        Base URL string without trailing slash
    """
    forwarded_proto = request.headers.get("X-Forwarded-Proto")
    forwarded_host = request.headers.get("X-Forwarded-Host")

    if forwarded_proto and forwarded_host:
        return f"{forwarded_proto}://{forwarded_host}"

    # Fallback to request.base_url
    base_url = str(request.base_url).rstrip("/")

    # Fix common proxy misconfiguration
    if forwarded_proto == "https" and base_url.startswith("http://"):
        base_url = base_url.replace("http://", "https://", 1)

    return base_url


def _create_error_response(
    error: str,
    error_code: str,
    status_code: int = 400,
    **extra_fields,
) -> JSONResponse:
    """Create standardized error response with CORS headers.

    Args:
        error: Human-readable error message
        error_code: Machine-readable error code
        status_code: HTTP status code
        **extra_fields: Additional fields to include

    Returns:
        JSONResponse with error details and CORS headers
    """
    body = {
        "error": error,
        "error_code": error_code,
    }
    if "hint" in extra_fields:
        body["hint"] = extra_fields.pop("hint")
    body.update(extra_fields)
    response = JSONResponse(body, status_code=status_code)
    return _add_cors_headers(response)


def _add_cors_headers(response: Response) -> Response:
    """Add CORS headers for browser access.

    Args:
        response: Starlette response object

    Returns:
        Response with CORS headers added
    """
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, HEAD, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Authorization"
    response.headers["Access-Control-Expose-Headers"] = (
        "Content-Disposition, Content-Length"
    )
    return response
