import hashlib
import hmac
import time

import pytest
from starlette.requests import Request

from amazon_ads_mcp.server.inbound_auth import (
    authorize_inbound_http,
    create_inbound_http_auth_middleware,
    verify_trusted_proxy_hmac,
)


def _request(
    path: str = "/mcp",
    *,
    query: str = "",
    headers: dict[str, str] | None = None,
    client: str = "203.0.113.10",
) -> Request:
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": path,
            "query_string": query.encode(),
            "headers": [
                (key.lower().encode(), value.encode())
                for key, value in (headers or {}).items()
            ],
            "client": (client, 12345),
            "scheme": "https",
            "server": ("example.test", 443),
        }
    )


def _signature(secret: str, timestamp: str, caller: str, method: str, path: str) -> str:
    msg = f"{timestamp}\n{caller}\n{method}\n{path}"
    return hmac.new(secret.encode(), msg.encode(), hashlib.sha256).hexdigest()


def test_direct_public_http_requires_caller_auth(monkeypatch):
    monkeypatch.delenv("MCP_ALLOW_UNAUTH_HTTP", raising=False)
    monkeypatch.delenv("MCP_TRUSTED_PROXY_HMAC_SECRET", raising=False)

    result = authorize_inbound_http(
        _request(), provider_type="direct", configured_host="0.0.0.0"
    )

    assert result.allowed is False
    assert result.reason == "caller_auth_required"


def test_direct_loopback_http_is_allowed(monkeypatch):
    monkeypatch.delenv("MCP_ALLOW_UNAUTH_HTTP", raising=False)

    result = authorize_inbound_http(
        _request(client="127.0.0.1"), provider_type="direct", configured_host="0.0.0.0"
    )

    assert result.allowed is True
    assert result.reason == "direct_loopback"


def test_openbridge_refresh_token_bearer_is_allowed(monkeypatch):
    monkeypatch.delenv("MCP_ALLOW_UNAUTH_HTTP", raising=False)
    token = "key12345678901234567890:secret12345678901234567890"

    result = authorize_inbound_http(
        _request(headers={"Authorization": f"Bearer {token}"}),
        provider_type="openbridge",
        configured_host="0.0.0.0",
    )

    assert result.allowed is True
    assert result.reason == "openbridge_bearer"


def test_static_bearer_token_is_allowed(monkeypatch):
    token = "s" * 32
    monkeypatch.delenv("MCP_ALLOW_UNAUTH_HTTP", raising=False)
    monkeypatch.delenv("MCP_TRUSTED_PROXY_HMAC_SECRET", raising=False)
    monkeypatch.setenv("MCP_INBOUND_TOKEN", token)

    result = authorize_inbound_http(
        _request(headers={"Authorization": f"Bearer {token}"}),
        provider_type="direct",
        configured_host="0.0.0.0",
    )

    assert result.allowed is True
    assert result.reason == "static_bearer"
    assert result.token_fingerprint == hashlib.sha256(token.encode()).hexdigest()[:8]


def test_static_bearer_token_rejects_wrong_value(monkeypatch):
    monkeypatch.delenv("MCP_ALLOW_UNAUTH_HTTP", raising=False)
    monkeypatch.delenv("MCP_TRUSTED_PROXY_HMAC_SECRET", raising=False)
    monkeypatch.setenv("MCP_INBOUND_TOKEN", "s" * 32)

    result = authorize_inbound_http(
        _request(headers={"Authorization": "Bearer wrong-token"}),
        provider_type="direct",
        configured_host="0.0.0.0",
    )

    assert result.allowed is False
    assert result.reason == "caller_auth_required"


def test_static_bearer_token_requires_minimum_length(monkeypatch):
    monkeypatch.setenv("MCP_INBOUND_TOKEN", "too-short")

    with pytest.raises(ValueError, match="MCP_INBOUND_TOKEN"):
        create_inbound_http_auth_middleware(
            auth_manager=None, configured_host="0.0.0.0"
        )


def test_trusted_proxy_hmac_includes_query_string(monkeypatch):
    secret = "s" * 32
    timestamp = str(int(time.time()))
    caller = "user-123"
    signature = _signature(secret, timestamp, caller, "POST", "/mcp?profile_id=A")
    monkeypatch.setenv("MCP_TRUSTED_PROXY_HMAC_SECRET", secret)

    ok = verify_trusted_proxy_hmac(
        _request(
            query="profile_id=A",
            headers={
                "X-MCP-Caller": caller,
                "X-MCP-Caller-Timestamp": timestamp,
                "X-MCP-Caller-Signature": signature,
            },
        )
    )
    tampered = verify_trusted_proxy_hmac(
        _request(
            query="profile_id=B",
            headers={
                "X-MCP-Caller": caller,
                "X-MCP-Caller-Timestamp": timestamp,
                "X-MCP-Caller-Signature": signature,
            },
        )
    )

    assert ok.allowed is True
    assert tampered.allowed is False
    assert tampered.reason == "trusted_proxy_signature_invalid"


def test_health_paths_are_unauthenticated(monkeypatch):
    monkeypatch.delenv("MCP_ALLOW_UNAUTH_HTTP", raising=False)

    result = authorize_inbound_http(
        _request("/healthz"), provider_type="direct", configured_host="0.0.0.0"
    )

    assert result.allowed is True
    assert result.reason == "health"


@pytest.mark.asyncio
async def test_inbound_middleware_allows_list_tools_without_caller_auth():
    middleware = create_inbound_http_auth_middleware(
        auth_manager=None, configured_host="0.0.0.0"
    )

    class Context:
        method = "tools/list"
        fastmcp_context = None

    async def call_next(_context):
        return "ok"

    assert await middleware.on_request(Context(), call_next) == "ok"


@pytest.mark.asyncio
async def test_inbound_middleware_uses_fastmcp_http_request_helper(monkeypatch):
    middleware = create_inbound_http_auth_middleware(
        auth_manager=None, configured_host="0.0.0.0"
    )

    class Context:
        method = "tools/call"
        fastmcp_context = None

    async def call_next(_context):
        return "ok"

    monkeypatch.setattr(
        "amazon_ads_mcp.server.inbound_auth.get_http_request",
        lambda: _request("/mcp"),
    )

    with pytest.raises(Exception, match="Authentication required"):
        await middleware.on_request(Context(), call_next)


@pytest.mark.asyncio
async def test_inbound_middleware_gates_call_tool_hook(monkeypatch):
    middleware = create_inbound_http_auth_middleware(
        auth_manager=None, configured_host="0.0.0.0"
    )

    class Context:
        method = "tools/call"
        fastmcp_context = None

    async def call_next(_context):
        return "ok"

    monkeypatch.setattr(
        "amazon_ads_mcp.server.inbound_auth.get_http_request",
        lambda: _request("/mcp"),
    )

    with pytest.raises(Exception, match="Authentication required"):
        await middleware.on_call_tool(Context(), call_next)
