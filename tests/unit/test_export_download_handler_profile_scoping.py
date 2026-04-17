"""Unit tests for ExportDownloadHandler profile scoping.

TDD: Tests written BEFORE implementation.
Run with: uv run pytest tests/unit/test_export_download_handler_profile_scoping.py -v
"""

import json
import tempfile
from pathlib import Path

import httpx
import pytest


# ---------------------------------------------------------------------------
# Shared transport helpers (streaming-compatible)
# ---------------------------------------------------------------------------


def _make_transport(
    payload: bytes = b'{"test": "data"}',
    *,
    content_type: str = "application/json",
    content_disposition: str = 'attachment; filename="test.json"',
) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        headers = {"content-type": content_type}
        if content_disposition:
            headers["content-disposition"] = content_disposition
        return httpx.Response(200, headers=headers, content=payload)

    return httpx.MockTransport(handler)


def _install_transport(monkeypatch, transport: httpx.MockTransport) -> None:
    real_client = httpx.AsyncClient

    def _factory(*args, **kwargs):
        kwargs["transport"] = transport
        return real_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", _factory)


@pytest.fixture(autouse=True)
def _bypass_ssrf(monkeypatch):
    from amazon_ads_mcp.utils import security

    monkeypatch.setattr(security, "validate_download_url", lambda url: url)


# =============================================================================
# Test: Profile-Scoped Resource Paths
# =============================================================================


class TestProfileScopedResourcePath:
    """Tests for profile-scoped directory paths."""

    @pytest.fixture
    def temp_base_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_get_resource_path_with_profile_id(self, temp_base_dir):
        from amazon_ads_mcp.utils.export_download_handler import (
            ExportDownloadHandler,
        )

        handler = ExportDownloadHandler(base_dir=temp_base_dir)

        path = handler.get_resource_path(
            url="https://advertising-api.amazon.com/exports/test.json",
            export_type="campaigns",
            profile_id="profile_123",
        )

        assert "profiles" in path.parts
        assert "profile_123" in path.parts
        assert path.exists()

    def test_get_resource_path_without_profile_id_is_legacy(self, temp_base_dir):
        from amazon_ads_mcp.utils.export_download_handler import (
            ExportDownloadHandler,
        )

        handler = ExportDownloadHandler(base_dir=temp_base_dir)

        path = handler.get_resource_path(
            url="https://advertising-api.amazon.com/exports/test.json",
            export_type="campaigns",
            profile_id=None,
        )

        assert "profiles" not in path.parts
        assert "exports" in path.parts or "downloads" in path.parts

    def test_profile_path_structure(self, temp_base_dir):
        from amazon_ads_mcp.utils.export_download_handler import (
            ExportDownloadHandler,
        )

        handler = ExportDownloadHandler(base_dir=temp_base_dir)

        path = handler.get_resource_path(
            url="https://advertising-api.amazon.com/exports/test.json",
            export_type="campaigns",
            profile_id="12345",
        )

        relative = path.relative_to(temp_base_dir)
        parts = relative.parts

        assert parts[0] == "profiles"
        assert parts[1] == "12345"
        assert len(parts) >= 3

    def test_different_profiles_get_different_directories(self, temp_base_dir):
        from amazon_ads_mcp.utils.export_download_handler import (
            ExportDownloadHandler,
        )

        handler = ExportDownloadHandler(base_dir=temp_base_dir)

        path1 = handler.get_resource_path(
            url="https://advertising-api.amazon.com/exports/test.json",
            export_type="campaigns",
            profile_id="profile_A",
        )
        path2 = handler.get_resource_path(
            url="https://advertising-api.amazon.com/exports/test.json",
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
    @pytest.fixture
    def temp_base_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.mark.asyncio
    async def test_download_export_with_profile_saves_to_profile_dir(
        self, temp_base_dir, monkeypatch
    ):
        from amazon_ads_mcp.utils.export_download_handler import (
            ExportDownloadHandler,
        )

        handler = ExportDownloadHandler(base_dir=temp_base_dir)
        _install_transport(monkeypatch, _make_transport())

        file_path = await handler.download_export(
            export_url="https://advertising-api.amazon.com/export.json",
            export_id="exp_123",
            export_type="campaigns",
            profile_id="profile_456",
        )

        assert "profiles" in file_path.parts
        assert "profile_456" in file_path.parts
        assert file_path.exists()

    @pytest.mark.asyncio
    async def test_download_export_without_profile_uses_legacy_path(
        self, temp_base_dir, monkeypatch
    ):
        from amazon_ads_mcp.utils.export_download_handler import (
            ExportDownloadHandler,
        )

        handler = ExportDownloadHandler(base_dir=temp_base_dir)
        _install_transport(monkeypatch, _make_transport())

        file_path = await handler.download_export(
            export_url="https://advertising-api.amazon.com/export.json",
            export_id="exp_123",
            export_type="campaigns",
        )

        assert "profiles" not in file_path.parts
        assert file_path.exists()

    @pytest.mark.asyncio
    async def test_metadata_includes_profile_id(
        self, temp_base_dir, monkeypatch
    ):
        from amazon_ads_mcp.utils.export_download_handler import (
            ExportDownloadHandler,
        )

        handler = ExportDownloadHandler(base_dir=temp_base_dir)
        _install_transport(monkeypatch, _make_transport())

        file_path = await handler.download_export(
            export_url="https://advertising-api.amazon.com/export.json",
            export_id="exp_123",
            export_type="campaigns",
            profile_id="profile_789",
            metadata={"custom": "data"},
        )

        meta_path = file_path.with_suffix(".meta.json")
        assert meta_path.exists()

        with open(meta_path) as f:
            meta = json.load(f)

        assert meta.get("profile_id") == "profile_789"


# =============================================================================
# Test: Handle Export Response with Profile
# =============================================================================


class TestHandleExportResponseWithProfile:
    @pytest.fixture
    def temp_base_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.mark.asyncio
    async def test_handle_export_response_with_profile_id(
        self, temp_base_dir, monkeypatch
    ):
        from amazon_ads_mcp.utils.export_download_handler import (
            ExportDownloadHandler,
        )

        handler = ExportDownloadHandler(base_dir=temp_base_dir)
        _install_transport(monkeypatch, _make_transport())

        export_response = {
            "status": "COMPLETED",
            "exportId": "exp_abc",
            "url": "https://advertising-api.amazon.com/download.json",
        }

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
    @pytest.fixture
    def temp_base_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)

            profile_dir = base / "profiles" / "profile_123" / "exports" / "campaigns"
            profile_dir.mkdir(parents=True)
            (profile_dir / "report1.json").write_text('{"test": 1}')
            (profile_dir / "report1.meta.json").write_text(
                '{"export_id": "exp1"}'
            )

            profile2_dir = base / "profiles" / "profile_456" / "exports" / "campaigns"
            profile2_dir.mkdir(parents=True)
            (profile2_dir / "report2.json").write_text('{"test": 2}')

            legacy_dir = base / "exports" / "campaigns"
            legacy_dir.mkdir(parents=True)
            (legacy_dir / "legacy_report.json").write_text('{"legacy": true}')

            yield base

    def test_list_downloads_for_specific_profile(self, temp_base_dir):
        from amazon_ads_mcp.utils.export_download_handler import (
            ExportDownloadHandler,
        )

        handler = ExportDownloadHandler(base_dir=temp_base_dir)

        files = handler.list_downloads(profile_id="profile_123")

        file_names = [f["name"] for f in files]
        assert "report1.json" in file_names
        assert "report2.json" not in file_names
        assert "legacy_report.json" not in file_names

    def test_list_downloads_without_profile_shows_legacy(self, temp_base_dir):
        from amazon_ads_mcp.utils.export_download_handler import (
            ExportDownloadHandler,
        )

        handler = ExportDownloadHandler(base_dir=temp_base_dir)

        files = handler.list_downloads(profile_id=None)

        file_names = [f["name"] for f in files]
        assert "legacy_report.json" in file_names
        assert "report1.json" not in file_names
        assert "report2.json" not in file_names

    def test_list_downloads_empty_profile_returns_empty(self, temp_base_dir):
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
    @pytest.fixture
    def temp_base_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_get_profile_base_dir_creates_directory(self, temp_base_dir):
        from amazon_ads_mcp.utils.export_download_handler import (
            ExportDownloadHandler,
        )

        handler = ExportDownloadHandler(base_dir=temp_base_dir)

        profile_dir = handler.get_profile_base_dir("my_profile")

        expected = temp_base_dir / "profiles" / "my_profile"
        assert profile_dir == expected
        assert profile_dir.exists()

    def test_get_profile_base_dir_returns_existing(self, temp_base_dir):
        from amazon_ads_mcp.utils.export_download_handler import (
            ExportDownloadHandler,
        )

        handler = ExportDownloadHandler(base_dir=temp_base_dir)

        expected = temp_base_dir / "profiles" / "existing_profile"
        expected.mkdir(parents=True)

        profile_dir = handler.get_profile_base_dir("existing_profile")

        assert profile_dir == expected

    def test_get_profile_base_dir_none_returns_base(self, temp_base_dir):
        from amazon_ads_mcp.utils.export_download_handler import (
            ExportDownloadHandler,
        )

        handler = ExportDownloadHandler(base_dir=temp_base_dir)

        profile_dir = handler.get_profile_base_dir(None)

        assert profile_dir == temp_base_dir
