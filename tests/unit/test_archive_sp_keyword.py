"""Tests for archive_sp_keyword.

SP v3 splits keyword archival from state transitions: PUT /sp/keywords
only accepts ENABLED/PAUSED (ARCHIVED → HTTP 400), and archival is
routed through POST /sp/keywords/delete with body
``{"keywordIdFilter": {"include": [<id>]}}``. Response is 207 with the
same `keywords.success` / `keywords.error` shape as PUT.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from amazon_ads_mcp.tools import campaign_management


class _FakeResponse:
    def __init__(self, status_code: int, payload: dict, text: str = ""):
        self.status_code = status_code
        self._payload = payload
        self.text = text

    def json(self) -> dict:
        return self._payload


def _patch_client(monkeypatch, resp: _FakeResponse) -> MagicMock:
    client = MagicMock()
    client.post = AsyncMock(return_value=resp)
    monkeypatch.setattr(
        "amazon_ads_mcp.utils.http_client.get_authenticated_client",
        AsyncMock(return_value=client),
    )
    return client


@pytest.mark.asyncio
async def test_archive_success_207(monkeypatch):
    client = _patch_client(
        monkeypatch,
        _FakeResponse(
            207,
            {"keywords": {"success": [{"index": 0, "keywordId": "K1"}], "error": []}},
        ),
    )

    result = await campaign_management.archive_sp_keyword(keyword_id="K1")

    assert result["success"] is True
    assert result["keyword_id"] == "K1"
    assert result["updated_fields"] == {"state": "ARCHIVED"}
    call = client.post.call_args
    assert call.args[0] == "/sp/keywords/delete"
    assert call.kwargs["json"] == {"keywordIdFilter": {"include": ["K1"]}}


@pytest.mark.asyncio
async def test_archive_error_list_207(monkeypatch):
    _patch_client(
        monkeypatch,
        _FakeResponse(
            207,
            {
                "keywords": {
                    "success": [],
                    "error": [
                        {"index": 0, "errors": [{"errorType": "INVALID_ARGUMENT"}]}
                    ],
                }
            },
        ),
    )

    result = await campaign_management.archive_sp_keyword(keyword_id="K_BAD")

    assert result["success"] is False
    assert result["keyword_id"] == "K_BAD"
    assert result["error"] == [{"errorType": "INVALID_ARGUMENT"}]


@pytest.mark.asyncio
async def test_archive_non_2xx(monkeypatch):
    _patch_client(monkeypatch, _FakeResponse(500, {}, text="upstream timeout"))

    result = await campaign_management.archive_sp_keyword(keyword_id="K2")

    assert result["success"] is False
    assert result["keyword_id"] == "K2"
    assert "HTTP 500" in result["error"]
    assert "upstream timeout" in result["error"]
