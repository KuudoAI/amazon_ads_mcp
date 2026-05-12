"""Smoke checks for the streamable HTTP MCP auth boundary.

These tests target a running server and are skipped unless
``ADS_MCP_SMOKE_URL`` is set, for example:

    ADS_MCP_SMOKE_URL=http://127.0.0.1:9080/mcp uv run pytest \
      --no-cov tests/smoke/test_http_mcp_auth_boundary.py
"""

from __future__ import annotations

import json
import os

import pytest

try:
    import httpx
except ImportError:  # pragma: no cover
    httpx = None


pytestmark = pytest.mark.skipif(
    not os.environ.get("ADS_MCP_SMOKE_URL") or httpx is None,
    reason="Set ADS_MCP_SMOKE_URL to run HTTP MCP smoke tests",
)


def _event_payload(response: "httpx.Response") -> dict:
    for line in response.text.splitlines():
        if line.startswith("data: "):
            return json.loads(line.removeprefix("data: "))
    raise AssertionError(f"No SSE data payload found: {response.text[:500]}")


def _post(url: str, payload: dict, session_id: str | None = None) -> "httpx.Response":
    headers = {
        "content-type": "application/json",
        "accept": "application/json, text/event-stream",
    }
    if session_id:
        headers["mcp-session-id"] = session_id
    return httpx.post(url, headers=headers, json=payload, timeout=10.0)


def test_http_mcp_discovery_open_and_tool_calls_gated():
    url = os.environ["ADS_MCP_SMOKE_URL"]
    health_url = url.removesuffix("/mcp") + "/health"

    health = httpx.get(health_url, timeout=10.0)
    assert health.status_code == 200
    assert health.json()["status"] == "healthy"

    init = _post(
        url,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "smoke", "version": "0"},
            },
        },
    )
    assert init.status_code == 200
    session_id = init.headers["mcp-session-id"]
    assert _event_payload(init)["result"]["serverInfo"]["name"]

    initialized = _post(
        url,
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        session_id=session_id,
    )
    assert initialized.status_code == 202

    tools = _post(
        url,
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        session_id=session_id,
    )
    assert tools.status_code == 200
    assert _event_payload(tools)["result"]["tools"]

    call = _post(
        url,
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "tags", "arguments": {}},
        },
        session_id=session_id,
    )
    assert call.status_code == 200
    payload = _event_payload(call)
    assert payload["result"]["isError"] is True
    envelope = json.loads(payload["result"]["content"][0]["text"])
    assert envelope["error_kind"] == "auth_error"
    assert envelope["error_code"] == "AUTHENTICATION_ERROR"
    assert "Authentication required" in envelope["details"][0]["issue"]
