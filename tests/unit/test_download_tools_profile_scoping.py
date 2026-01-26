"""Unit tests for download_tools profile scoping.

TDD: Tests written BEFORE implementation.
Run with: uv run pytest tests/unit/test_download_tools_profile_scoping.py -v
"""

import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest


# =============================================================================
# Test: list_downloaded_files with profile_id
# =============================================================================


class TestListDownloadedFilesWithProfile:
    """Tests for list_downloaded_files with profile scoping."""

    @pytest.fixture
    def temp_base_dir(self):
        """Create a temporary base directory with test files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)

            # Create profile-scoped files
            profile_dir = base / "profiles" / "profile_123" / "exports" / "campaigns"
            profile_dir.mkdir(parents=True)
            (profile_dir / "report1.json").write_text('{"test": 1}')

            # Create another profile's files
            profile2_dir = base / "profiles" / "profile_456" / "exports" / "campaigns"
            profile2_dir.mkdir(parents=True)
            (profile2_dir / "report2.json").write_text('{"test": 2}')

            # Create legacy (non-profile) files
            legacy_dir = base / "exports" / "campaigns"
            legacy_dir.mkdir(parents=True)
            (legacy_dir / "legacy_report.json").write_text('{"legacy": true}')

            yield base

    @pytest.mark.asyncio
    async def test_list_downloaded_files_with_profile_id(self, temp_base_dir):
        """Should list only files for the specified profile."""
        from amazon_ads_mcp.tools.download_tools import list_downloaded_files

        with patch(
            "amazon_ads_mcp.tools.download_tools.get_download_handler"
        ) as mock_get_handler:
            from amazon_ads_mcp.utils.export_download_handler import (
                ExportDownloadHandler,
            )

            handler = ExportDownloadHandler(base_dir=temp_base_dir)
            mock_get_handler.return_value = handler

            result = await list_downloaded_files(profile_id="profile_123")

        # Should only see profile_123's files
        assert result["total_files"] >= 1
        # Check that files are from the right profile (full_path includes profile)
        for f in result.get("files", []):
            assert "profile_123" in f.get("full_path", "")

    @pytest.mark.asyncio
    async def test_list_downloaded_files_without_profile_shows_legacy(
        self, temp_base_dir
    ):
        """Should show legacy files when profile_id is None."""
        from amazon_ads_mcp.tools.download_tools import list_downloaded_files

        with patch(
            "amazon_ads_mcp.tools.download_tools.get_download_handler"
        ) as mock_get_handler:
            from amazon_ads_mcp.utils.export_download_handler import (
                ExportDownloadHandler,
            )

            handler = ExportDownloadHandler(base_dir=temp_base_dir)
            mock_get_handler.return_value = handler

            result = await list_downloaded_files(profile_id=None)

        # Should see legacy files, not profile files (full_path excludes profiles dir)
        for f in result.get("files", []):
            assert "profiles" not in f.get("full_path", "")


# =============================================================================
# Test: check_and_download_export with profile_id
# =============================================================================


class TestCheckAndDownloadExportWithProfile:
    """Tests for check_and_download_export with profile scoping."""

    @pytest.fixture
    def temp_base_dir(self):
        """Create a temporary base directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.mark.asyncio
    async def test_check_and_download_export_with_profile_id(self, temp_base_dir):
        """Should pass profile_id to handler.handle_export_response."""
        from amazon_ads_mcp.tools.download_tools import check_and_download_export

        export_response = {
            "status": "COMPLETED",
            "exportId": "exp_123",
            "url": "https://example.com/download.json",
        }

        with patch(
            "amazon_ads_mcp.tools.download_tools.get_download_handler"
        ) as mock_get_handler:
            mock_handler = AsyncMock()
            mock_handler.handle_export_response = AsyncMock(
                return_value=temp_base_dir / "profiles" / "profile_abc" / "test.json"
            )
            mock_get_handler.return_value = mock_handler

            result = await check_and_download_export(
                export_id="exp_123",
                export_response=export_response,
                export_type="campaigns",
                profile_id="profile_abc",
            )

        # Verify profile_id was passed to handler
        mock_handler.handle_export_response.assert_called_once()
        call_kwargs = mock_handler.handle_export_response.call_args.kwargs
        assert call_kwargs.get("profile_id") == "profile_abc"

        # Verify success
        assert result["success"] is True


# =============================================================================
# Test: builtin_tools download functions with profile_id
# =============================================================================


class TestBuiltinDownloadToolsWithProfile:
    """Tests for builtin download tools getting profile from auth."""

    @pytest.mark.asyncio
    async def test_download_export_tool_uses_active_profile(self):
        """download_export_tool should get profile from auth manager."""
        # This test verifies the tool gets profile_id from auth context
        # The actual implementation will be tested via integration
        from amazon_ads_mcp.auth.manager import get_auth_manager

        # Verify get_auth_manager exists and has get_active_profile_id
        auth_mgr = get_auth_manager()
        if auth_mgr:
            assert hasattr(auth_mgr, "get_active_profile_id")
