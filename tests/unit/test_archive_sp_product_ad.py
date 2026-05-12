"""Tests for archive_sp_product_ad.

SP v3 splits product-ad archival from state transitions: PUT /sp/productAds
only accepts ENABLED/PAUSED (ARCHIVED → HTTP 400), and archival is
routed through POST /sp/productAds/delete. The filter key is
``adIdFilter`` (NOT ``productAdIdFilter``) because the ID field on a
product ad is ``adId``. Response is 207 with `productAds.success` /
`productAds.error` arrays.
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
            {"productAds": {"success": [{"index": 0, "adId": "AD1"}], "error": []}},
        ),
    )

    result = await campaign_management.archive_sp_product_ad(ad_id="AD1")

    assert result["success"] is True
    assert result["ad_id"] == "AD1"
    assert result["updated_fields"] == {"state": "ARCHIVED"}
    # Body shape uses adIdFilter, NOT productAdIdFilter.
    call = client.post.call_args
    assert call.args[0] == "/sp/productAds/delete"
    assert call.kwargs["json"] == {"adIdFilter": {"include": ["AD1"]}}


@pytest.mark.asyncio
async def test_archive_error_list_207(monkeypatch):
    _patch_client(
        monkeypatch,
        _FakeResponse(
            207,
            {
                "productAds": {
                    "success": [],
                    "error": [
                        {"index": 0, "errors": [{"errorType": "INVALID_ARGUMENT"}]}
                    ],
                }
            },
        ),
    )

    result = await campaign_management.archive_sp_product_ad(ad_id="AD_BAD")

    assert result["success"] is False
    assert result["ad_id"] == "AD_BAD"
    assert result["error"] == [{"errorType": "INVALID_ARGUMENT"}]


@pytest.mark.asyncio
async def test_archive_non_2xx(monkeypatch):
    _patch_client(monkeypatch, _FakeResponse(500, {}, text="upstream timeout"))

    result = await campaign_management.archive_sp_product_ad(ad_id="AD2")

    assert result["success"] is False
    assert result["ad_id"] == "AD2"
    assert "HTTP 500" in result["error"]
    assert "upstream timeout" in result["error"]
