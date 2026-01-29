"""Unit tests for file download routes.

TDD: These tests are written BEFORE the implementation.
Run with: uv run pytest tests/unit/test_file_routes.py -v
"""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest


# =============================================================================
# Test: Path Validation & Security
# =============================================================================


class TestPathValidation:
    """Tests for _validate_file_access security function."""

    @pytest.fixture
    def temp_base_dir(self):
        """Create a temporary base directory for testing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir) / "profiles" / "test_profile"
            base.mkdir(parents=True)
            yield base

    def test_valid_path_within_base_allowed(self, temp_base_dir):
        """Valid file path within base directory should be allowed."""
        from amazon_ads_mcp.server.file_routes import _validate_file_access

        # Create a valid file
        valid_file = temp_base_dir / "exports" / "report.json"
        valid_file.parent.mkdir(parents=True, exist_ok=True)
        valid_file.write_text('{"test": true}')

        result = _validate_file_access(valid_file, temp_base_dir)
        assert result is None  # None means access allowed

    def test_path_traversal_blocked(self, temp_base_dir):
        """Path traversal attempts (../) should be blocked."""
        from amazon_ads_mcp.server.file_routes import _validate_file_access

        # Attempt to escape via ../
        malicious_path = temp_base_dir / ".." / ".." / "etc" / "passwd"

        result = _validate_file_access(malicious_path, temp_base_dir)
        assert result is not None
        assert result["error_code"] == "PATH_TRAVERSAL"

    def test_absolute_path_outside_base_blocked(self, temp_base_dir):
        """Absolute paths outside base directory should be blocked."""
        from amazon_ads_mcp.server.file_routes import _validate_file_access

        # Attempt to access absolute path
        absolute_path = Path("/etc/passwd")

        result = _validate_file_access(absolute_path, temp_base_dir)
        assert result is not None
        assert "PATH_TRAVERSAL" in result.get("error_code", "")

    def test_sensitive_env_file_blocked(self, temp_base_dir):
        """Sensitive files like .env should be blocked."""
        from amazon_ads_mcp.server.file_routes import _validate_file_access

        sensitive_file = temp_base_dir / ".env"
        sensitive_file.touch()

        result = _validate_file_access(sensitive_file, temp_base_dir)
        assert result is not None
        assert result["error_code"] == "SENSITIVE_FILE"

    def test_sensitive_credentials_file_blocked(self, temp_base_dir):
        """Files containing 'credentials' in name should be blocked."""
        from amazon_ads_mcp.server.file_routes import _validate_file_access

        sensitive_file = temp_base_dir / "credentials.json"
        sensitive_file.touch()

        result = _validate_file_access(sensitive_file, temp_base_dir)
        assert result is not None
        assert result["error_code"] == "SENSITIVE_FILE"

    def test_sensitive_key_file_blocked(self, temp_base_dir):
        """Files with .key extension should be blocked."""
        from amazon_ads_mcp.server.file_routes import _validate_file_access

        sensitive_file = temp_base_dir / "private.key"
        sensitive_file.touch()

        result = _validate_file_access(sensitive_file, temp_base_dir)
        assert result is not None
        assert result["error_code"] == "SENSITIVE_FILE"

    def test_sensitive_pem_file_blocked(self, temp_base_dir):
        """Files with .pem extension should be blocked."""
        from amazon_ads_mcp.server.file_routes import _validate_file_access

        sensitive_file = temp_base_dir / "certificate.pem"
        sensitive_file.touch()

        result = _validate_file_access(sensitive_file, temp_base_dir)
        assert result is not None
        assert result["error_code"] == "SENSITIVE_FILE"

    def test_file_too_large_blocked(self, temp_base_dir):
        """Files exceeding max size should be blocked."""
        from amazon_ads_mcp.server.file_routes import _validate_file_access

        # Create a file and mock its size
        large_file = temp_base_dir / "large_report.json"
        large_file.write_text("x")  # Small actual content

        # Mock the file size check
        with patch.object(Path, "stat") as mock_stat:
            mock_stat.return_value.st_size = 1024 * 1024 * 1024  # 1GB

            # Mock settings to have a small max size
            with patch(
                "amazon_ads_mcp.server.file_routes.settings"
            ) as mock_settings:
                mock_settings.download_max_file_size = 512 * 1024 * 1024  # 512MB

                result = _validate_file_access(large_file, temp_base_dir)
                assert result is not None
                assert result["error_code"] == "FILE_TOO_LARGE"

    def test_extension_whitelist_enforced(self, temp_base_dir):
        """When extension whitelist is set, only allowed extensions pass."""
        from amazon_ads_mcp.server.file_routes import _validate_file_access

        # Create an executable file
        exe_file = temp_base_dir / "script.exe"
        exe_file.touch()

        with patch(
            "amazon_ads_mcp.server.file_routes.settings"
        ) as mock_settings:
            mock_settings.download_max_file_size = 512 * 1024 * 1024
            mock_settings.download_allowed_extensions = ".json,.csv,.txt"

            result = _validate_file_access(exe_file, temp_base_dir)
            assert result is not None
            assert result["error_code"] == "EXTENSION_NOT_ALLOWED"

    def test_allowed_extension_passes_whitelist(self, temp_base_dir):
        """Files with allowed extensions should pass whitelist check."""
        from amazon_ads_mcp.server.file_routes import _validate_file_access

        json_file = temp_base_dir / "report.json"
        json_file.write_text('{"test": true}')

        with patch(
            "amazon_ads_mcp.server.file_routes.settings"
        ) as mock_settings:
            mock_settings.download_max_file_size = 512 * 1024 * 1024
            mock_settings.download_allowed_extensions = ".json,.csv,.txt"

            result = _validate_file_access(json_file, temp_base_dir)
            assert result is None  # Allowed


# =============================================================================
# Test: Media Type Detection
# =============================================================================


class TestMediaTypeDetection:
    """Tests for _get_media_type function."""

    def test_json_media_type(self):
        """JSON files should return application/json."""
        from amazon_ads_mcp.server.file_routes import _get_media_type

        assert _get_media_type(Path("report.json")) == "application/json"

    def test_csv_media_type(self):
        """CSV files should return text/csv."""
        from amazon_ads_mcp.server.file_routes import _get_media_type

        assert _get_media_type(Path("data.csv")) == "text/csv"

    def test_tsv_media_type(self):
        """TSV files should return text/tab-separated-values."""
        from amazon_ads_mcp.server.file_routes import _get_media_type

        assert _get_media_type(Path("data.tsv")) == "text/tab-separated-values"

    def test_txt_media_type(self):
        """TXT files should return text/plain."""
        from amazon_ads_mcp.server.file_routes import _get_media_type

        assert _get_media_type(Path("readme.txt")) == "text/plain"

    def test_xml_media_type(self):
        """XML files should return application/xml."""
        from amazon_ads_mcp.server.file_routes import _get_media_type

        assert _get_media_type(Path("config.xml")) == "application/xml"

    def test_gzip_media_type(self):
        """GZ files should return application/gzip."""
        from amazon_ads_mcp.server.file_routes import _get_media_type

        assert _get_media_type(Path("archive.gz")) == "application/gzip"

    def test_zip_media_type(self):
        """ZIP files should return application/zip."""
        from amazon_ads_mcp.server.file_routes import _get_media_type

        assert _get_media_type(Path("archive.zip")) == "application/zip"

    def test_jsonl_media_type(self):
        """JSONL files should return application/x-ndjson."""
        from amazon_ads_mcp.server.file_routes import _get_media_type

        assert _get_media_type(Path("stream.jsonl")) == "application/x-ndjson"

    def test_unknown_extension_returns_octet_stream(self):
        """Unknown extensions should return application/octet-stream."""
        from amazon_ads_mcp.server.file_routes import _get_media_type

        assert _get_media_type(Path("file.xyz")) == "application/octet-stream"
        assert _get_media_type(Path("noextension")) == "application/octet-stream"

    def test_case_insensitive(self):
        """Extension matching should be case-insensitive."""
        from amazon_ads_mcp.server.file_routes import _get_media_type

        assert _get_media_type(Path("FILE.JSON")) == "application/json"
        assert _get_media_type(Path("DATA.CSV")) == "text/csv"


# =============================================================================
# Test: Profile Directory Management
# =============================================================================


class TestProfileDirectory:
    """Tests for _get_profile_base_dir function."""

    def test_creates_profile_directory(self):
        """Should create profile directory if it doesn't exist."""
        from amazon_ads_mcp.server.file_routes import _get_profile_base_dir

        with tempfile.TemporaryDirectory() as tmpdir:
            handler = Mock()
            handler.base_dir = Path(tmpdir)

            profile_dir = _get_profile_base_dir(handler, "profile_123")

            expected = Path(tmpdir) / "profiles" / "profile_123"
            assert profile_dir == expected
            assert profile_dir.exists()
            assert profile_dir.is_dir()

    def test_returns_existing_profile_directory(self):
        """Should return existing profile directory."""
        from amazon_ads_mcp.server.file_routes import _get_profile_base_dir

        with tempfile.TemporaryDirectory() as tmpdir:
            # Pre-create the directory
            existing = Path(tmpdir) / "profiles" / "existing_profile"
            existing.mkdir(parents=True)

            handler = Mock()
            handler.base_dir = Path(tmpdir)

            profile_dir = _get_profile_base_dir(handler, "existing_profile")

            assert profile_dir == existing

    def test_raises_on_empty_profile_id(self):
        """Should raise ValueError when profile_id is empty."""
        from amazon_ads_mcp.server.file_routes import _get_profile_base_dir

        handler = Mock()
        handler.base_dir = Path("/tmp")

        with pytest.raises(ValueError, match="Profile ID required"):
            _get_profile_base_dir(handler, "")

    def test_raises_on_none_profile_id(self):
        """Should raise ValueError when profile_id is None."""
        from amazon_ads_mcp.server.file_routes import _get_profile_base_dir

        handler = Mock()
        handler.base_dir = Path("/tmp")

        with pytest.raises(ValueError, match="Profile ID required"):
            _get_profile_base_dir(handler, None)


# =============================================================================
# Test: File Path Resolution
# =============================================================================


class TestFileResolution:
    """Tests for _resolve_file_path function."""

    @pytest.fixture
    def temp_profile_dir(self):
        """Create a temporary profile directory with test files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            profile_dir = Path(tmpdir)

            # Create test file structure
            exports_dir = profile_dir / "exports" / "campaigns"
            exports_dir.mkdir(parents=True)

            # Create a data file
            data_file = exports_dir / "report.json"
            data_file.write_text('{"campaigns": []}')

            # Create metadata file
            meta_file = exports_dir / "report.json.meta.json"
            meta_file.write_text(
                json.dumps(
                    {
                        "export_id": "exp_abc123",
                        "export_type": "campaigns",
                    }
                )
            )

            yield profile_dir

    def test_resolves_direct_path(self, temp_profile_dir):
        """Should resolve direct relative paths."""
        from amazon_ads_mcp.server.file_routes import _resolve_file_path

        result = _resolve_file_path(
            "exports/campaigns/report.json", temp_profile_dir
        )

        assert result is not None
        assert result.name == "report.json"
        assert result.exists()

    def test_resolves_export_id_from_metadata(self, temp_profile_dir):
        """Should resolve export_id by looking up metadata files."""
        from amazon_ads_mcp.server.file_routes import _resolve_file_path

        result = _resolve_file_path("exp_abc123", temp_profile_dir)

        assert result is not None
        assert result.name == "report.json"

    def test_returns_none_for_nonexistent_path(self, temp_profile_dir):
        """Should return None for non-existent paths."""
        from amazon_ads_mcp.server.file_routes import _resolve_file_path

        result = _resolve_file_path("nonexistent/file.json", temp_profile_dir)

        assert result is None

    def test_returns_none_for_unknown_export_id(self, temp_profile_dir):
        """Should return None for unknown export IDs."""
        from amazon_ads_mcp.server.file_routes import _resolve_file_path

        result = _resolve_file_path("unknown_export_id", temp_profile_dir)

        assert result is None

    def test_returns_none_for_directory(self, temp_profile_dir):
        """Should return None if path points to a directory."""
        from amazon_ads_mcp.server.file_routes import _resolve_file_path

        result = _resolve_file_path("exports/campaigns", temp_profile_dir)

        assert result is None


# =============================================================================
# Test: Authentication
# =============================================================================


class TestDownloadAuth:
    """Tests for _verify_download_auth function."""

    @pytest.fixture
    def mock_request(self):
        """Create a mock Starlette request."""
        request = Mock()
        request.headers = {}
        return request

    @pytest.mark.asyncio
    async def test_auth_disabled_allows_access(self, mock_request):
        """When no auth token configured, all requests allowed."""
        from amazon_ads_mcp.server.file_routes import _verify_download_auth

        with patch.dict(os.environ, {}, clear=True):
            with patch(
                "amazon_ads_mcp.server.file_routes.settings"
            ) as mock_settings:
                mock_settings.download_auth_token = None

                result = await _verify_download_auth(mock_request)

                assert result is None  # Access allowed

    @pytest.mark.asyncio
    async def test_missing_token_returns_401(self, mock_request):
        """When auth enabled but no token provided, return 401."""
        from amazon_ads_mcp.server.file_routes import _verify_download_auth

        with patch(
            "amazon_ads_mcp.server.file_routes.settings"
        ) as mock_settings:
            mock_settings.download_auth_token = "secret_token"

            result = await _verify_download_auth(mock_request)

            assert result is not None
            assert result.status_code == 401

    @pytest.mark.asyncio
    async def test_invalid_token_returns_401(self, mock_request):
        """When wrong token provided, return 401."""
        from amazon_ads_mcp.server.file_routes import _verify_download_auth

        mock_request.headers = {"Authorization": "Bearer wrong_token"}

        with patch(
            "amazon_ads_mcp.server.file_routes.settings"
        ) as mock_settings:
            mock_settings.download_auth_token = "correct_token"

            result = await _verify_download_auth(mock_request)

            assert result is not None
            assert result.status_code == 401

    @pytest.mark.asyncio
    async def test_valid_bearer_token_allows_access(self, mock_request):
        """Valid Bearer token should allow access."""
        from amazon_ads_mcp.server.file_routes import _verify_download_auth

        mock_request.headers = {"Authorization": "Bearer secret_token"}

        with patch(
            "amazon_ads_mcp.server.file_routes.settings"
        ) as mock_settings:
            mock_settings.download_auth_token = "secret_token"

            result = await _verify_download_auth(mock_request)

            assert result is None  # Access allowed

    @pytest.mark.asyncio
    async def test_malformed_auth_header_returns_401(self, mock_request):
        """Malformed Authorization header should return 401."""
        from amazon_ads_mcp.server.file_routes import _verify_download_auth

        mock_request.headers = {"Authorization": "Basic base64stuff"}

        with patch(
            "amazon_ads_mcp.server.file_routes.settings"
        ) as mock_settings:
            mock_settings.download_auth_token = "secret_token"

            result = await _verify_download_auth(mock_request)

            assert result is not None
            assert result.status_code == 401

    @pytest.mark.asyncio
    async def test_env_var_fallback(self, mock_request):
        """Should fall back to DOWNLOAD_AUTH_TOKEN env var."""
        from amazon_ads_mcp.server.file_routes import _verify_download_auth

        mock_request.headers = {"Authorization": "Bearer env_token"}

        with patch(
            "amazon_ads_mcp.server.file_routes.settings"
        ) as mock_settings:
            mock_settings.download_auth_token = None

            with patch.dict(os.environ, {"DOWNLOAD_AUTH_TOKEN": "env_token"}):
                result = await _verify_download_auth(mock_request)

                assert result is None  # Access allowed


# =============================================================================
# Test: Base URL Resolution
# =============================================================================


class TestBaseUrlResolution:
    """Tests for _get_base_url function."""

    def test_uses_forwarded_headers(self):
        """Should use X-Forwarded-Proto and X-Forwarded-Host when present."""
        from amazon_ads_mcp.server.file_routes import _get_base_url

        request = Mock()
        request.headers = {
            "X-Forwarded-Proto": "https",
            "X-Forwarded-Host": "api.example.com",
        }
        request.base_url = "http://localhost:9080/"

        result = _get_base_url(request)

        assert result == "https://api.example.com"

    def test_falls_back_to_request_base_url(self):
        """Should fall back to request.base_url when no forwarded headers."""
        from amazon_ads_mcp.server.file_routes import _get_base_url

        request = Mock()
        request.headers = {}
        request.base_url = "http://localhost:9080/"

        result = _get_base_url(request)

        assert result == "http://localhost:9080"

    def test_strips_trailing_slash(self):
        """Should strip trailing slash from base URL."""
        from amazon_ads_mcp.server.file_routes import _get_base_url

        request = Mock()
        request.headers = {}
        request.base_url = "http://localhost:9080/"

        result = _get_base_url(request)

        assert not result.endswith("/")

    def test_fixes_http_to_https_with_forwarded_proto(self):
        """Should upgrade HTTP to HTTPS when X-Forwarded-Proto is https."""
        from amazon_ads_mcp.server.file_routes import _get_base_url

        request = Mock()
        request.headers = {"X-Forwarded-Proto": "https"}
        request.base_url = "http://localhost:9080/"

        result = _get_base_url(request)

        assert result.startswith("https://")


# =============================================================================
# Test: Error Response Format
# =============================================================================


class TestErrorResponse:
    """Tests for _create_error_response function."""

    def test_creates_json_response(self):
        """Should create a JSONResponse with correct structure."""
        from amazon_ads_mcp.server.file_routes import _create_error_response

        response = _create_error_response(
            error="Something went wrong",
            error_code="TEST_ERROR",
            status_code=400,
        )

        assert response.status_code == 400
        # Check response body contains expected fields
        body = json.loads(response.body.decode())
        assert body["error"] == "Something went wrong"
        assert body["error_code"] == "TEST_ERROR"

    def test_includes_hint_when_provided(self):
        """Should include hint field when provided."""
        from amazon_ads_mcp.server.file_routes import _create_error_response

        response = _create_error_response(
            error="File not found",
            error_code="NOT_FOUND",
            status_code=404,
            hint="Check the file path",
        )

        body = json.loads(response.body.decode())
        assert body["hint"] == "Check the file path"

    def test_includes_extra_fields(self):
        """Should include extra fields in response."""
        from amazon_ads_mcp.server.file_routes import _create_error_response

        response = _create_error_response(
            error="File not found",
            error_code="NOT_FOUND",
            status_code=404,
            file_path="/some/path",
            profile_id="123",
        )

        body = json.loads(response.body.decode())
        assert body["file_path"] == "/some/path"
        assert body["profile_id"] == "123"

    def test_error_response_includes_cors_headers(self):
        """Error responses should include CORS headers for browser access."""
        from amazon_ads_mcp.server.file_routes import _create_error_response

        response = _create_error_response(
            error="Test error",
            error_code="TEST_ERROR",
            status_code=400,
        )

        # Verify CORS headers are present
        assert response.headers.get("Access-Control-Allow-Origin") == "*"
        assert "GET" in response.headers.get("Access-Control-Allow-Methods", "")
        assert "Authorization" in response.headers.get(
            "Access-Control-Allow-Headers", ""
        )


# =============================================================================
# Test: CORS Headers
# =============================================================================


class TestCorsHeaders:
    """Tests for _add_cors_headers function."""

    def test_adds_cors_headers(self):
        """Should add all required CORS headers."""
        from amazon_ads_mcp.server.file_routes import _add_cors_headers
        from starlette.responses import Response

        response = Response(content="test")
        result = _add_cors_headers(response)

        assert result.headers["Access-Control-Allow-Origin"] == "*"
        assert "GET" in result.headers["Access-Control-Allow-Methods"]
        assert "Authorization" in result.headers["Access-Control-Allow-Headers"]
        assert (
            "Content-Disposition"
            in result.headers["Access-Control-Expose-Headers"]
        )


# =============================================================================
# Test: Profile Context Retrieval
# =============================================================================


class TestGetCurrentProfileId:
    """Tests for _get_current_profile_id function."""

    @pytest.mark.asyncio
    async def test_returns_profile_from_auth_manager(self):
        """Should return profile ID from auth manager."""
        from amazon_ads_mcp.server.file_routes import _get_current_profile_id

        with patch(
            "amazon_ads_mcp.server.file_routes.get_auth_manager"
        ) as mock_get_auth:
            mock_auth_mgr = Mock()
            mock_auth_mgr.get_active_profile_id.return_value = "profile_456"
            mock_get_auth.return_value = mock_auth_mgr

            result = await _get_current_profile_id()

            assert result == "profile_456"

    @pytest.mark.asyncio
    async def test_returns_none_when_no_auth_manager(self):
        """Should return None when auth manager not available."""
        from amazon_ads_mcp.server.file_routes import _get_current_profile_id

        with patch(
            "amazon_ads_mcp.server.file_routes.get_auth_manager"
        ) as mock_get_auth:
            mock_get_auth.return_value = None

            result = await _get_current_profile_id()

            assert result is None

    @pytest.mark.asyncio
    async def test_returns_none_when_no_active_profile(self):
        """Should return None when no active profile set."""
        from amazon_ads_mcp.server.file_routes import _get_current_profile_id

        with patch(
            "amazon_ads_mcp.server.file_routes.get_auth_manager"
        ) as mock_get_auth:
            mock_auth_mgr = Mock()
            mock_auth_mgr.get_active_profile_id.return_value = None
            mock_get_auth.return_value = mock_auth_mgr

            result = await _get_current_profile_id()

            assert result is None


# =============================================================================
# Test: Response Models
# =============================================================================


class TestGetDownloadUrlResponse:
    """Tests for GetDownloadUrlResponse model."""

    def test_success_response(self):
        """Should create successful response with all fields."""
        from amazon_ads_mcp.models.builtin_responses import GetDownloadUrlResponse

        response = GetDownloadUrlResponse(
            success=True,
            download_url="http://localhost:9080/downloads/report.json",
            file_name="report.json",
            size_bytes=1234,
            profile_id="profile_123",
            instructions="Use HTTP GET to download the file",
        )

        assert response.success is True
        assert response.download_url == "http://localhost:9080/downloads/report.json"
        assert response.file_name == "report.json"
        assert response.size_bytes == 1234
        assert response.profile_id == "profile_123"
        assert response.instructions == "Use HTTP GET to download the file"
        assert response.error is None

    def test_error_response(self):
        """Should create error response with error and hint."""
        from amazon_ads_mcp.models.builtin_responses import GetDownloadUrlResponse

        response = GetDownloadUrlResponse(
            success=False,
            error="File not found",
            hint="Use list_downloads to see available files",
        )

        assert response.success is False
        assert response.error == "File not found"
        assert response.hint == "Use list_downloads to see available files"
        assert response.download_url is None


# =============================================================================
# Test: Route Registration
# =============================================================================


class TestRouteRegistration:
    """Tests for register_file_routes function."""

    def test_registers_routes_on_http_server(self):
        """Should register routes when server has custom_route."""
        from amazon_ads_mcp.server.file_routes import register_file_routes

        # Mock server with custom_route capability
        mock_server = Mock()
        mock_server.custom_route = Mock(return_value=lambda f: f)

        register_file_routes(mock_server)

        # Should have called custom_route multiple times
        assert mock_server.custom_route.call_count >= 2

    def test_skips_registration_without_custom_route(self):
        """Should skip registration when server lacks custom_route."""
        from amazon_ads_mcp.server.file_routes import register_file_routes

        # Mock server without custom_route
        mock_server = Mock(spec=[])  # No custom_route attribute

        # Should not raise, just log warning
        register_file_routes(mock_server)
