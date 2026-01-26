"""Unit tests for ExportDownloadHandler profile scoping.

TDD: Tests written BEFORE implementation.
Run with: uv run pytest tests/unit/test_export_download_handler_profile_scoping.py -v
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import pytest


# =============================================================================
# Test: Profile-Scoped Resource Paths
# =============================================================================


class TestProfileScopedResourcePath:
    """Tests for profile-scoped directory paths."""

    @pytest.fixture
    def temp_base_dir(self):
        """Create a temporary base directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_get_resource_path_with_profile_id(self, temp_base_dir):
        """Should return profile-scoped path when profile_id provided."""
        from amazon_ads_mcp.utils.export_download_handler import (
            ExportDownloadHandler,
        )

        handler = ExportDownloadHandler(base_dir=temp_base_dir)

        path = handler.get_resource_path(
            url="https://example.com/exports/test.json",
            export_type="campaigns",
            profile_id="profile_123",
        )

        # Should be under profiles/{profile_id}/
        assert "profiles" in path.parts
        assert "profile_123" in path.parts
        assert path.exists()

    def test_get_resource_path_without_profile_id_is_legacy(self, temp_base_dir):
        """Should return legacy path when profile_id is None (backward compat)."""
        from amazon_ads_mcp.utils.export_download_handler import (
            ExportDownloadHandler,
        )

        handler = ExportDownloadHandler(base_dir=temp_base_dir)

        path = handler.get_resource_path(
            url="https://example.com/exports/test.json",
            export_type="campaigns",
            profile_id=None,
        )

        # Should NOT be under profiles/
        assert "profiles" not in path.parts
        # Should still have resource type
        assert "exports" in path.parts or "downloads" in path.parts

    def test_profile_path_structure(self, temp_base_dir):
        """Profile path should follow: profiles/{profile_id}/{resource_type}/{sub_type}."""
        from amazon_ads_mcp.utils.export_download_handler import (
            ExportDownloadHandler,
        )

        handler = ExportDownloadHandler(base_dir=temp_base_dir)

        path = handler.get_resource_path(
            url="https://example.com/exports/test.json",
            export_type="campaigns",
            profile_id="12345",
        )

        # Verify structure
        relative = path.relative_to(temp_base_dir)
        parts = relative.parts

        assert parts[0] == "profiles"
        assert parts[1] == "12345"
        # Resource type and sub_type follow
        assert len(parts) >= 3

    def test_different_profiles_get_different_directories(self, temp_base_dir):
        """Different profile IDs should result in different directories."""
        from amazon_ads_mcp.utils.export_download_handler import (
            ExportDownloadHandler,
        )

        handler = ExportDownloadHandler(base_dir=temp_base_dir)

        path1 = handler.get_resource_path(
            url="https://example.com/exports/test.json",
            export_type="campaigns",
            profile_id="profile_A",
        )
        path2 = handler.get_resource_path(
            url="https://example.com/exports/test.json",
            export_type="campaigns",
            profile_id="profile_B",
        )

        assert path1 != path2
        assert "profile_A" in str(path1)
        assert "profile_B" in str(path2)


# =============================================================================
# Test: Profile-Scoped Downloads
# =============================================================================


class TestProfileScopedDownload:
    """Tests for profile-scoped file downloads."""

    @pytest.fixture
    def temp_base_dir(self):
        """Create a temporary base directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def mock_httpx_response(self):
        """Create a mock httpx response."""
        response = Mock()
        response.content = b'{"test": "data"}'
        response.headers = {
            "content-type": "application/json",
            "content-disposition": 'attachment; filename="test.json"',
        }
        response.raise_for_status = Mock()
        return response

    @pytest.mark.asyncio
    async def test_download_export_with_profile_saves_to_profile_dir(
        self, temp_base_dir, mock_httpx_response
    ):
        """Downloads with profile_id should save to profile-scoped directory."""
        from amazon_ads_mcp.utils.export_download_handler import (
            ExportDownloadHandler,
        )

        handler = ExportDownloadHandler(base_dir=temp_base_dir)

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_httpx_response)
            mock_client_class.return_value.__aenter__ = AsyncMock(
                return_value=mock_client
            )
            mock_client_class.return_value.__aexit__ = AsyncMock()

            file_path = await handler.download_export(
                export_url="https://example.com/export.json",
                export_id="exp_123",
                export_type="campaigns",
                profile_id="profile_456",
            )

        # Verify file is under profile directory
        assert "profiles" in file_path.parts
        assert "profile_456" in file_path.parts
        assert file_path.exists()

    @pytest.mark.asyncio
    async def test_download_export_without_profile_uses_legacy_path(
        self, temp_base_dir, mock_httpx_response
    ):
        """Downloads without profile_id should use legacy path (backward compat)."""
        from amazon_ads_mcp.utils.export_download_handler import (
            ExportDownloadHandler,
        )

        handler = ExportDownloadHandler(base_dir=temp_base_dir)

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_httpx_response)
            mock_client_class.return_value.__aenter__ = AsyncMock(
                return_value=mock_client
            )
            mock_client_class.return_value.__aexit__ = AsyncMock()

            file_path = await handler.download_export(
                export_url="https://example.com/export.json",
                export_id="exp_123",
                export_type="campaigns",
                # No profile_id
            )

        # Verify file is NOT under profile directory
        assert "profiles" not in file_path.parts
        assert file_path.exists()

    @pytest.mark.asyncio
    async def test_metadata_includes_profile_id(
        self, temp_base_dir, mock_httpx_response
    ):
        """Metadata should include profile_id when provided."""
        from amazon_ads_mcp.utils.export_download_handler import (
            ExportDownloadHandler,
        )

        handler = ExportDownloadHandler(base_dir=temp_base_dir)

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_httpx_response)
            mock_client_class.return_value.__aenter__ = AsyncMock(
                return_value=mock_client
            )
            mock_client_class.return_value.__aexit__ = AsyncMock()

            file_path = await handler.download_export(
                export_url="https://example.com/export.json",
                export_id="exp_123",
                export_type="campaigns",
                profile_id="profile_789",
                metadata={"custom": "data"},
            )

        # Check metadata file (with_suffix replaces extension)
        meta_path = file_path.with_suffix(".meta.json")
        assert meta_path.exists()

        with open(meta_path) as f:
            meta = json.load(f)

        assert meta.get("profile_id") == "profile_789"


# =============================================================================
# Test: Handle Export Response with Profile
# =============================================================================


class TestHandleExportResponseWithProfile:
    """Tests for handle_export_response with profile scoping."""

    @pytest.fixture
    def temp_base_dir(self):
        """Create a temporary base directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def mock_httpx_response(self):
        """Create a mock httpx response."""
        response = Mock()
        response.content = b'{"test": "data"}'
        response.headers = {
            "content-type": "application/json",
        }
        response.raise_for_status = Mock()
        return response

    @pytest.mark.asyncio
    async def test_handle_export_response_with_profile_id(
        self, temp_base_dir, mock_httpx_response
    ):
        """handle_export_response should pass profile_id to download_export."""
        from amazon_ads_mcp.utils.export_download_handler import (
            ExportDownloadHandler,
        )

        handler = ExportDownloadHandler(base_dir=temp_base_dir)

        export_response = {
            "status": "COMPLETED",
            "exportId": "exp_abc",
            "url": "https://example.com/download.json",
        }

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_httpx_response)
            mock_client_class.return_value.__aenter__ = AsyncMock(
                return_value=mock_client
            )
            mock_client_class.return_value.__aexit__ = AsyncMock()

            file_path = await handler.handle_export_response(
                export_response=export_response,
                export_type="campaigns",
                profile_id="profile_handle_test",
            )

        assert file_path is not None
        assert "profiles" in file_path.parts
        assert "profile_handle_test" in file_path.parts


# =============================================================================
# Test: List Downloads with Profile Scoping
# =============================================================================


class TestListDownloadsWithProfile:
    """Tests for listing downloads with profile scoping."""

    @pytest.fixture
    def temp_base_dir(self):
        """Create a temporary base directory with test files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)

            # Create profile-scoped files
            profile_dir = base / "profiles" / "profile_123" / "exports" / "campaigns"
            profile_dir.mkdir(parents=True)
            (profile_dir / "report1.json").write_text('{"test": 1}')
            (profile_dir / "report1.meta.json").write_text(
                '{"export_id": "exp1"}'
            )

            # Create another profile's files
            profile2_dir = base / "profiles" / "profile_456" / "exports" / "campaigns"
            profile2_dir.mkdir(parents=True)
            (profile2_dir / "report2.json").write_text('{"test": 2}')

            # Create legacy (non-profile) files
            legacy_dir = base / "exports" / "campaigns"
            legacy_dir.mkdir(parents=True)
            (legacy_dir / "legacy_report.json").write_text('{"legacy": true}')

            yield base

    def test_list_downloads_for_specific_profile(self, temp_base_dir):
        """Should only list files for the specified profile."""
        from amazon_ads_mcp.utils.export_download_handler import (
            ExportDownloadHandler,
        )

        handler = ExportDownloadHandler(base_dir=temp_base_dir)

        files = handler.list_downloads(profile_id="profile_123")

        # Should only see profile_123's files
        file_names = [f["name"] for f in files]
        assert "report1.json" in file_names
        assert "report2.json" not in file_names  # Different profile
        assert "legacy_report.json" not in file_names  # Legacy

    def test_list_downloads_without_profile_shows_legacy(self, temp_base_dir):
        """Without profile_id, should show legacy (non-profile) files."""
        from amazon_ads_mcp.utils.export_download_handler import (
            ExportDownloadHandler,
        )

        handler = ExportDownloadHandler(base_dir=temp_base_dir)

        files = handler.list_downloads(profile_id=None)

        # Should see legacy files
        file_names = [f["name"] for f in files]
        assert "legacy_report.json" in file_names
        # Should NOT see profile-scoped files
        assert "report1.json" not in file_names
        assert "report2.json" not in file_names

    def test_list_downloads_empty_profile_returns_empty(self, temp_base_dir):
        """Should return empty list for profile with no downloads."""
        from amazon_ads_mcp.utils.export_download_handler import (
            ExportDownloadHandler,
        )

        handler = ExportDownloadHandler(base_dir=temp_base_dir)

        files = handler.list_downloads(profile_id="nonexistent_profile")

        assert files == []


# =============================================================================
# Test: Get Profile Base Directory
# =============================================================================


class TestGetProfileBaseDir:
    """Tests for getting the profile-specific base directory."""

    @pytest.fixture
    def temp_base_dir(self):
        """Create a temporary base directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_get_profile_base_dir_creates_directory(self, temp_base_dir):
        """Should create and return profile base directory."""
        from amazon_ads_mcp.utils.export_download_handler import (
            ExportDownloadHandler,
        )

        handler = ExportDownloadHandler(base_dir=temp_base_dir)

        profile_dir = handler.get_profile_base_dir("my_profile")

        expected = temp_base_dir / "profiles" / "my_profile"
        assert profile_dir == expected
        assert profile_dir.exists()

    def test_get_profile_base_dir_returns_existing(self, temp_base_dir):
        """Should return existing profile directory without error."""
        from amazon_ads_mcp.utils.export_download_handler import (
            ExportDownloadHandler,
        )

        handler = ExportDownloadHandler(base_dir=temp_base_dir)

        # Create it first
        expected = temp_base_dir / "profiles" / "existing_profile"
        expected.mkdir(parents=True)

        profile_dir = handler.get_profile_base_dir("existing_profile")

        assert profile_dir == expected

    def test_get_profile_base_dir_none_returns_base(self, temp_base_dir):
        """Should return base_dir when profile_id is None."""
        from amazon_ads_mcp.utils.export_download_handler import (
            ExportDownloadHandler,
        )

        handler = ExportDownloadHandler(base_dir=temp_base_dir)

        profile_dir = handler.get_profile_base_dir(None)

        # Should return base_dir for legacy mode
        assert profile_dir == temp_base_dir
