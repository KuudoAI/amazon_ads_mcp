"""Unit tests for export download handler.

This module tests the export download functionality that handles
downloading and processing Amazon Ads API exports.
"""

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, patch, MagicMock

from amazon_ads_mcp.utils.export_download_handler import ExportDownloadHandler


async def _run_download(tmp_path: Path):
    h = ExportDownloadHandler(base_dir=tmp_path)
    
    # Create mock response
    mock_response = AsyncMock()
    mock_response.headers = {
        "content-disposition": 'attachment; filename="report.csv"',
        "content-type": "text/csv",
    }
    mock_response.content = b"a,b\n1,2\n"
    mock_response.raise_for_status = MagicMock()
    
    # Create mock client with async context manager support
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    
    # Patch the httpx.AsyncClient constructor to return our mock
    with patch('httpx.AsyncClient') as mock_async_client:
        mock_async_client.return_value = mock_client
        
        out = await h.download_export(
            export_url="https://offline-report-storage.s3.amazonaws.com/exports/abc",
            export_id="abc",
            export_type="campaigns",
            metadata={"k": "v"},
        )
    return out


def test_download_export_writes_file(tmp_path: Path):
    out = asyncio.run(_run_download(tmp_path))
    assert out.exists()
    meta = out.with_suffix(".meta.json")
    assert meta.exists()
