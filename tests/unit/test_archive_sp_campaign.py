"""Tests for archive_sp_campaign.

Retroactive parity coverage for the v3 archive-endpoint trap fix
originally shipped in cac7889. SP v3 splits campaign archival from
state transitions: PUT /sp/campaigns only accepts ENABLED/PAUSED
(ARCHIVED → HTTP 400), and archival is routed through
POST /sp/campaigns/delete with body
``{"campaignIdFilter": {"include": [<id>]}}``. Response is 207 with
the same `campaigns.success` / `campaigns.error` shape as PUT.

Matches the test contract of the four sibling archive_sp_* tools added
in 218ec19, 9d2e9e9, dcb8139, 28dd860.
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
            {"campaigns": {"success": [{"index": 0, "campaignId": "C1"}], "error": []}},
        ),
    )

    result = await campaign_management.archive_sp_campaign(campaign_id="C1")

    assert result["success"] is True
    assert result["campaign_id"] == "C1"
    assert result["updated_fields"] == {"state": "ARCHIVED"}
    call = client.post.call_args
    assert call.args[0] == "/sp/campaigns/delete"
    assert call.kwargs["json"] == {"campaignIdFilter": {"include": ["C1"]}}


@pytest.mark.asyncio
async def test_archive_error_list_207(monkeypatch):
    _patch_client(
        monkeypatch,
        _FakeResponse(
            207,
            {
                "campaigns": {
                    "success": [],
                    "error": [
                        {"index": 0, "errors": [{"errorType": "INVALID_ARGUMENT"}]}
                    ],
                }
            },
        ),
    )

    result = await campaign_management.archive_sp_campaign(campaign_id="C_BAD")

    assert result["success"] is False
    assert result["campaign_id"] == "C_BAD"
    assert result["error"] == [{"errorType": "INVALID_ARGUMENT"}]


@pytest.mark.asyncio
async def test_archive_non_2xx(monkeypatch):
    _patch_client(monkeypatch, _FakeResponse(500, {}, text="upstream timeout"))

    result = await campaign_management.archive_sp_campaign(campaign_id="C2")

    assert result["success"] is False
    assert result["campaign_id"] == "C2"
    assert "HTTP 500" in result["error"]
    assert "upstream timeout" in result["error"]
