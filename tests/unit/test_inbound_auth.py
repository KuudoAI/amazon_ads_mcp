import hashlib
import hmac
import time
from types import SimpleNamespace

import pytest
from starlette.requests import Request

from amazon_ads_mcp.auth.base import ProviderConfig
from amazon_ads_mcp.auth.providers.kuudo import (
    KuudoAmazonAdsProvider,
    KuudoConfigError,
)
from amazon_ads_mcp.server.inbound_auth import (
    authorize_inbound_http,
    create_inbound_http_auth_middleware,
    is_loopback_host,
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


@pytest.mark.parametrize(
    "host",
    ["::1", "[::1]", "[::1]:9080", "127.0.0.1:9080", "localhost:9080"],
)
def test_loopback_host_accepts_ipv6_and_host_port_forms(host):
    assert is_loopback_host(host) is True


@pytest.mark.parametrize(
    "host", ["[::1", "[::1]invalid", "::2", "example.com:9080", "localhost:http"]
)
def test_loopback_host_rejects_non_loopback_and_malformed_forms(host):
    assert is_loopback_host(host) is False


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


def test_kuudo_api_key_bearer_is_allowed(monkeypatch):
    monkeypatch.delenv("MCP_ALLOW_UNAUTH_HTTP", raising=False)
    token = "sk_test_client_supplied"

    result = authorize_inbound_http(
        _request(headers={"Authorization": f"Bearer {token}"}),
        provider_type="kuudo",
        configured_host="0.0.0.0",
    )

    assert result.allowed is True
    assert result.reason == "kuudo_bearer"


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


@pytest.mark.asyncio
async def test_inbound_middleware_scopes_kuudo_bearer_to_tool_call(monkeypatch):
    monkeypatch.delenv("KUUDO_API_KEY", raising=False)
    monkeypatch.delenv("MCP_INBOUND_TOKEN", raising=False)
    provider = KuudoAmazonAdsProvider(
        ProviderConfig(
            base_url="https://app.kuudo.test",
            provider="amazon_ads",
        )
    )
    middleware = create_inbound_http_auth_middleware(
        auth_manager=SimpleNamespace(provider=provider),
        configured_host="0.0.0.0",
    )

    class Context:
        method = "tools/call"
        fastmcp_context = None

    token = "sk_test_client_supplied"
    monkeypatch.setattr(
        "amazon_ads_mcp.server.inbound_auth.get_http_request",
        lambda: _request(headers={"Authorization": f"Bearer {token}"}),
    )

    async def call_next(_context):
        assert provider._get_effective_api_key() == token
        return "ok"

    assert await middleware.on_call_tool(Context(), call_next) == "ok"
    with pytest.raises(KuudoConfigError):
        provider._get_effective_api_key()


@pytest.mark.asyncio
async def test_kuudo_bearer_swap_clears_persisted_tenant_state_before_tool_call(
    monkeypatch,
):
    from datetime import datetime, timedelta, timezone

    from amazon_ads_mcp.auth.session_state import (
        get_active_credentials,
        get_active_identity,
        get_active_profiles,
        get_last_seen_token_fingerprint,
        get_state_reset_reason,
        reset_all_session_state,
        set_active_credentials,
        set_active_identity,
        set_active_profiles,
    )
    from amazon_ads_mcp.middleware.auth_session_bridge import AUTH_SESSION_STATE_KEY
    from amazon_ads_mcp.middleware.authentication import AuthSessionStateMiddleware
    from amazon_ads_mcp.models import AuthCredentials, Identity

    monkeypatch.delenv("KUUDO_API_KEY", raising=False)
    monkeypatch.delenv("MCP_INBOUND_TOKEN", raising=False)
    reset_all_session_state()

    provider = KuudoAmazonAdsProvider(
        ProviderConfig(
            base_url="https://app.kuudo.test",
            provider="amazon_ads",
        )
    )
    auth_manager = SimpleNamespace(
        provider=provider,
        get_active_region=lambda: "na",
    )
    inbound = create_inbound_http_auth_middleware(
        auth_manager=auth_manager,
        configured_host="0.0.0.0",
    )
    session_bridge = AuthSessionStateMiddleware()

    class SessionContext:
        def __init__(self):
            self.request_context = SimpleNamespace(request=None)
            self.state = {}

        async def get_state(self, key):
            return self.state.get(key)

        async def set_state(self, key, value):
            self.state[key] = value

    session_context = SessionContext()

    class Context:
        method = "tools/call"
        fastmcp_context = session_context

    async def run_call(bearer, tool_call):
        session_context.request_context.request = _request(
            headers={"Authorization": f"Bearer {bearer}"}
        )

        async def call_session_bridge(context):
            return await session_bridge.on_request(context, tool_call)

        return await inbound.on_call_tool(Context(), call_session_bridge)

    token_a = "sk_test_tenant_a"
    token_b = "sk_test_tenant_b"

    async def select_tenant_a(_context):
        set_active_identity(
            Identity(id="tenant-a-identity", type="kuudo", attributes={})
        )
        set_active_credentials(
            AuthCredentials(
                identity_id="tenant-a-identity",
                access_token="tenant-a-access-token",
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            )
        )
        set_active_profiles({"tenant-a-identity": "profile-a"})
        return "selected"

    try:
        assert await run_call(token_a, select_tenant_a) == "selected"

        persisted = session_context.state[AUTH_SESSION_STATE_KEY]
        assert persisted["active_identity"]["id"] == "tenant-a-identity"
        assert persisted[
            "last_seen_token_fingerprint"
        ] == provider.session_api_key_fingerprint(token_a)
        assert persisted["last_seen_token_fingerprint"] != hashlib.sha256(
            token_a.encode("utf-8")
        ).hexdigest()

        # FastMCP may dispatch the next request in a fresh async context.
        reset_all_session_state()

        async def execute_again_as_tenant_a(_context):
            assert provider._get_effective_api_key() == token_a
            assert get_active_identity().id == "tenant-a-identity"
            assert get_active_credentials().access_token == "tenant-a-access-token"
            assert get_active_profiles() == {"tenant-a-identity": "profile-a"}
            assert (
                get_last_seen_token_fingerprint()
                == provider.session_api_key_fingerprint(token_a)
            )
            assert get_state_reset_reason() is None
            return "preserved"

        assert await run_call(token_a, execute_again_as_tenant_a) == "preserved"

        reset_all_session_state()

        async def execute_as_tenant_b(_context):
            assert provider._get_effective_api_key() == token_b
            assert get_active_identity() is None
            assert get_active_credentials() is None
            assert get_active_profiles() == {}
            assert (
                get_last_seen_token_fingerprint()
                == provider.session_api_key_fingerprint(token_b)
            )
            assert get_state_reset_reason() == "token_swapped"
            return "ok"

        assert await run_call(token_b, execute_as_tenant_b) == "ok"
        assert get_state_reset_reason() is None

        persisted = session_context.state[AUTH_SESSION_STATE_KEY]
        assert persisted["active_identity"] is None
        assert persisted["active_credentials"] is None
        assert persisted["active_profiles"] == {}
        assert persisted[
            "last_seen_token_fingerprint"
        ] == provider.session_api_key_fingerprint(token_b)
    finally:
        reset_all_session_state()
