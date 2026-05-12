"""Tests for outbound auth hook redaction."""

from __future__ import annotations

import logging
from unittest.mock import AsyncMock

import httpx
import pytest

from amazon_ads_mcp.auth.hooks import AuthHeaderHook


def _make_request(headers: dict | None = None) -> httpx.Request:
    return httpx.Request(
        "GET",
        "https://advertising-api.amazon.com/v2/profiles",
        headers=headers or {},
    )


@pytest.mark.asyncio
async def test_before_request_debug_logging_redacts_auth_headers(caplog):
    auth_manager = AsyncMock()
    auth_manager.get_headers.return_value = {
        "Authorization": "Bearer token-that-must-not-be-logged",
        "Amazon-Advertising-API-ClientId": "client-id",
    }
    hook = AuthHeaderHook(auth_manager)

    with caplog.at_level(logging.DEBUG):
        await hook.before_request(_make_request())

    msgs = " ".join(rec.message for rec in caplog.records)
    assert "token-that-must-not-be-logged" not in msgs
    assert "<REDACTED" in msgs


@pytest.mark.asyncio
async def test_after_response_redacts_credential_values_from_logs(caplog):
    hook = AuthHeaderHook(AsyncMock())
    secret = "a" * 40
    response = httpx.Response(
        401,
        request=_make_request(headers={"Authorization": "Bearer request-token"}),
        text=f"invalid token {secret}",
    )

    with caplog.at_level(logging.ERROR):
        await hook.after_response(response)

    msgs = " ".join(rec.message for rec in caplog.records)
    assert secret not in msgs
    assert "request-token" not in msgs
    assert "<api_key:REDACTED>" in msgs
