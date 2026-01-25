import base64
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from amazon_ads_mcp.tools import download_tools


class FakeHandler:
    def __init__(self, base_dir: Path, file_path: Path | None = None):
        self.base_dir = base_dir
        self.file_path = file_path
        self.calls = []
        self.downloads = {}

    async def handle_export_response(self, export_response, export_type=None):
        self.calls.append({"export_response": export_response, "export_type": export_type})
        return self.file_path

    def list_downloads(self, resource_type=None):
        return self.downloads


@pytest.mark.asyncio
async def test_check_and_download_export_downloaded(monkeypatch, tmp_path):
    export_id = base64.b64encode(b"export,C").decode("ascii").rstrip("=")
    file_path = tmp_path / "file.csv"
    handler = FakeHandler(tmp_path, file_path=file_path)
    monkeypatch.setattr(download_tools, "get_download_handler", lambda: handler)

    export_response = {"status": "COMPLETED", "url": "http://example.com"}
    result = await download_tools.check_and_download_export(export_id, export_response)

    assert result["success"] is True
    assert result["status"] == "downloaded"
    assert result["file_path"] == str(file_path)
    assert handler.calls[0]["export_type"] == "campaigns"


@pytest.mark.asyncio
async def test_check_and_download_export_processing(monkeypatch, tmp_path):
    handler = FakeHandler(tmp_path, file_path=None)
    monkeypatch.setattr(download_tools, "get_download_handler", lambda: handler)

    export_response = {"status": "PROCESSING"}
    result = await download_tools.check_and_download_export("id", export_response)

    assert result["success"] is False
    assert result["status"] == "processing"


@pytest.mark.asyncio
async def test_check_and_download_export_failed(monkeypatch, tmp_path):
    handler = FakeHandler(tmp_path, file_path=None)
    monkeypatch.setattr(download_tools, "get_download_handler", lambda: handler)

    export_response = {"status": "FAILED", "error": {"message": "bad"}}
    result = await download_tools.check_and_download_export("id", export_response)

    assert result["success"] is False
    assert result["status"] == "failed"
    assert result["error"]["message"] == "bad"


@pytest.mark.asyncio
async def test_list_downloaded_files_summarizes(monkeypatch, tmp_path):
    handler = FakeHandler(tmp_path)
    handler.downloads = {
        "exports/campaigns": [
            {"size": 10},
            {"size": 5},
        ],
        "reports/general": [{"size": 20}],
    }
    monkeypatch.setattr(download_tools, "get_download_handler", lambda: handler)

    result = await download_tools.list_downloaded_files()

    assert result["total_files"] == 3
    assert result["total_size_bytes"] == 35
    assert result["downloads"] == handler.downloads


@pytest.mark.asyncio
async def test_get_download_metadata_reads_meta(tmp_path):
    file_path = tmp_path / "export.csv"
    file_path.write_text("data")
    meta_path = file_path.with_suffix(".meta.json")
    meta_path.write_text('{"foo": "bar"}')

    result = await download_tools.get_download_metadata(str(file_path))

    assert result["success"] is True
    assert result["metadata"]["foo"] == "bar"


@pytest.mark.asyncio
async def test_get_download_metadata_missing_file(tmp_path):
    missing_path = tmp_path / "missing.csv"

    result = await download_tools.get_download_metadata(str(missing_path))

    assert result["success"] is False
    assert result["error"] == "File not found"


@pytest.mark.asyncio
async def test_clean_old_downloads_removes_files(monkeypatch, tmp_path):
    base_dir = tmp_path / "data"
    resource_dir = base_dir / "exports" / "campaigns"
    resource_dir.mkdir(parents=True)

    old_file = resource_dir / "old.csv"
    old_file.write_text("old")
    old_meta = old_file.with_suffix(".meta.json")
    old_meta.write_text("{}")

    new_file = resource_dir / "new.csv"
    new_file.write_text("new")

    old_time = (datetime.now() - timedelta(days=10)).timestamp()
    new_time = (datetime.now() - timedelta(days=1)).timestamp()
    old_file.chmod(0o600)
    new_file.chmod(0o600)
    old_file.touch()
    new_file.touch()
    import os

    os.utime(old_file, (old_time, old_time))
    os.utime(new_file, (new_time, new_time))

    handler = FakeHandler(base_dir)
    monkeypatch.setattr(download_tools, "get_download_handler", lambda: handler)

    result = await download_tools.clean_old_downloads(resource_type="exports", days_old=7)

    assert result["success"] is True
    assert result["deleted_files"] == 1
    assert not old_file.exists()
    assert not old_meta.exists()
    assert new_file.exists()
