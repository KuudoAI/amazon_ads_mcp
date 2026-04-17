"""Unit tests for export download handler.

This module tests the export download functionality that handles
downloading and processing Amazon Ads API exports.
"""

import asyncio
import gzip
import hashlib
import json
from pathlib import Path

import httpx
import pytest

from amazon_ads_mcp.utils.errors import DownloadTooLargeError
from amazon_ads_mcp.utils.export_download_handler import ExportDownloadHandler


def _make_transport(
    payload: bytes,
    *,
    content_type: str = "text/csv",
    content_disposition: str = 'attachment; filename="report.csv"',
    content_length: int | None = None,
):
    """Build a MockTransport that yields ``payload`` for any GET.

    Uses streaming bytes so the handler exercises ``aiter_bytes``.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        headers = {"content-type": content_type}
        if content_disposition:
            headers["content-disposition"] = content_disposition
        if content_length is not None:
            headers["content-length"] = str(content_length)
        return httpx.Response(200, headers=headers, content=payload)

    return httpx.MockTransport(handler)


@pytest.fixture(autouse=True)
def _patch_mock_transport(monkeypatch):
    """Each test that needs transport injection calls ``_install(payload)``.

    Exposes a helper on the fixture via ``request.node``.
    """
    yield


def _install_transport(monkeypatch, transport: httpx.MockTransport) -> None:
    real_client = httpx.AsyncClient

    def _factory(*args, **kwargs):
        kwargs["transport"] = transport
        return real_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", _factory)


@pytest.fixture(autouse=True)
def _bypass_ssrf(monkeypatch):
    """Disable SSRF network resolution in tests."""
    from amazon_ads_mcp.utils import security

    monkeypatch.setattr(security, "validate_download_url", lambda url: url)


def _download_url() -> str:
    return "https://offline-report-storage.s3.amazonaws.com/exports/abc"


def test_download_export_writes_file(tmp_path: Path, monkeypatch):
    handler = ExportDownloadHandler(base_dir=tmp_path)
    payload = b"a,b\n1,2\n"
    _install_transport(monkeypatch, _make_transport(payload))

    out = asyncio.run(
        handler.download_export(
            export_url=_download_url(),
            export_id="abc",
            export_type="campaigns",
            metadata={"k": "v"},
        )
    )

    assert out.exists()
    assert out.read_bytes() == payload
    meta = out.with_suffix(".meta.json")
    assert meta.exists()
    meta_obj = json.loads(meta.read_text())
    assert meta_obj["file_size"] == len(payload)
    # URL must NOT be persisted raw; hash only.
    assert "original_url" not in meta_obj
    assert meta_obj["original_url_sha256"] == hashlib.sha256(
        _download_url().encode()
    ).hexdigest()


def test_download_export_aborts_when_over_cap(tmp_path: Path, monkeypatch):
    handler = ExportDownloadHandler(base_dir=tmp_path)

    # Cap to 128 bytes; payload is 1 KiB so streaming must trip over it.
    from amazon_ads_mcp.config import settings as settings_mod

    monkeypatch.setattr(
        settings_mod.settings, "download_max_file_size", 128, raising=False
    )

    payload = b"x" * 1024
    _install_transport(monkeypatch, _make_transport(payload))

    with pytest.raises(DownloadTooLargeError):
        asyncio.run(
            handler.download_export(
                export_url=_download_url(),
                export_id="abc",
                export_type="campaigns",
            )
        )

    # No partial file should remain.
    leftovers = list(
        (tmp_path).rglob("*.csv")
    ) + list((tmp_path).rglob("*.bin"))
    assert leftovers == []


def test_download_export_rejects_on_content_length(tmp_path: Path, monkeypatch):
    handler = ExportDownloadHandler(base_dir=tmp_path)

    from amazon_ads_mcp.config import settings as settings_mod

    monkeypatch.setattr(
        settings_mod.settings, "download_max_file_size", 128, raising=False
    )

    payload = b"x" * 64  # under cap, but advertise over cap
    _install_transport(
        monkeypatch,
        _make_transport(payload, content_length=10_000),
    )

    with pytest.raises(DownloadTooLargeError):
        asyncio.run(
            handler.download_export(
                export_url=_download_url(),
                export_id="abc",
                export_type="campaigns",
            )
        )


def test_download_export_streams_gzip(tmp_path: Path, monkeypatch):
    handler = ExportDownloadHandler(base_dir=tmp_path)
    raw = b"col1,col2\n1,2\n3,4\n"
    gz = gzip.compress(raw)
    _install_transport(
        monkeypatch,
        _make_transport(
            gz,
            content_type="application/gzip",
            content_disposition='attachment; filename="report.csv.gz"',
        ),
    )

    out = asyncio.run(
        handler.download_export(
            export_url=_download_url(),
            export_id="abc",
            export_type="campaigns",
        )
    )

    # The decompressed sibling becomes the final path
    assert out.suffix == ".csv"
    assert out.exists()
    assert out.read_bytes() == raw
    # Original .gz is preserved next to it
    gz_path = out.with_suffix(".csv.gz")
    assert gz_path.exists()
