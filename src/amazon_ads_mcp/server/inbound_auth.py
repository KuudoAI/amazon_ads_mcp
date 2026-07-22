"""Inbound HTTP authorization helpers for MCP and custom routes."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
from dataclasses import dataclass
from ipaddress import ip_address
from typing import Any

from fastmcp.exceptions import ToolError
from fastmcp.server.dependencies import get_http_request
from fastmcp.server.middleware import Middleware, MiddlewareContext
from starlette.middleware import Middleware as StarletteMiddleware
from starlette.requests import Request
from starlette.responses import Response

from ..auth.session_state import (
    bind_request_tenant_fingerprint,
    reset_request_tenant_token,
    set_state_reset_reason,
)
from ..exceptions import AuthenticationError
from ..middleware.error_envelope import build_envelope_from_exception, envelope_to_json

logger = logging.getLogger(__name__)

ALLOW_UNAUTH_HTTP_ENV = "MCP_ALLOW_UNAUTH_HTTP"
INBOUND_TOKEN_ENV = "MCP_INBOUND_TOKEN"
PROXY_SECRET_ENV = "MCP_TRUSTED_PROXY_HMAC_SECRET"
PROXY_CALLER_HEADER_ENV = "MCP_TRUSTED_PROXY_CALLER_HEADER"
PROXY_SIGNATURE_HEADER_ENV = "MCP_TRUSTED_PROXY_SIGNATURE_HEADER"
PROXY_TIMESTAMP_HEADER_ENV = "MCP_TRUSTED_PROXY_TIMESTAMP_HEADER"

DEFAULT_CALLER_HEADER = "X-MCP-Caller"
DEFAULT_SIGNATURE_HEADER = "X-MCP-Caller-Signature"
DEFAULT_TIMESTAMP_HEADER = "X-MCP-Caller-Timestamp"
MAX_PROXY_CLOCK_SKEW_SECONDS = 300

HEALTH_PATHS = {"/", "/health", "/healthz"}
OAUTH_CALLBACK_PATHS = {"/auth/callback"}
AUTH_REQUIRED_MESSAGE = (
    "Authentication required: MCP HTTP caller authorization is required"
)


@dataclass(frozen=True)
class InboundAuthResult:
    allowed: bool
    reason: str
    caller_id: str | None = None
    token_fingerprint: str | None = None


def token_fingerprint(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:8]


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def is_allow_unauth_http_enabled() -> bool:
    return _truthy(os.getenv(ALLOW_UNAUTH_HTTP_ENV))


def is_loopback_host(host: str | None) -> bool:
    if not host or not isinstance(host, str):
        return False
    normalized = host.strip().lower()
    if normalized.startswith("["):
        closing_bracket = normalized.find("]")
        if closing_bracket == -1:
            return False
        suffix = normalized[closing_bracket + 1 :]
        if suffix and not (suffix.startswith(":") and suffix[1:].isdigit()):
            return False
        normalized = normalized[1:closing_bracket]
    else:
        try:
            return ip_address(normalized).is_loopback
        except ValueError:
            if normalized.count(":") == 1:
                normalized, port = normalized.split(":", 1)
                if not port.isdigit():
                    return False

    if normalized == "localhost":
        return True
    try:
        return ip_address(normalized).is_loopback
    except ValueError:
        return False


def request_is_loopback(request: Request | None, configured_host: str | None) -> bool:
    if is_loopback_host(configured_host):
        return True
    if request is None or request.client is None:
        return False
    return is_loopback_host(request.client.host)


def extract_bearer_token(request: Request) -> str | None:
    auth_header = request.headers.get("authorization", "")
    parts = auth_header.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1].strip() or None


def is_openbridge_refresh_token(token: str | None) -> bool:
    return bool(token and ":" in token and len(token) > 20)


def get_static_bearer_token() -> str | None:
    token = (os.getenv(INBOUND_TOKEN_ENV) or "").strip()
    if not token:
        return None
    if len(token.encode("utf-8")) < 32:
        raise ValueError(f"{INBOUND_TOKEN_ENV} must be at least 32 bytes")
    return token


def verify_static_bearer(request: Request) -> InboundAuthResult:
    configured_token = get_static_bearer_token()
    if not configured_token:
        return InboundAuthResult(False, "static_bearer_not_configured")

    bearer = extract_bearer_token(request)
    if bearer and hmac.compare_digest(bearer, configured_token):
        return InboundAuthResult(
            True,
            "static_bearer",
            caller_id="static-bearer",
            token_fingerprint=token_fingerprint(bearer),
        )
    return InboundAuthResult(False, "static_bearer_invalid")


def verify_trusted_proxy_hmac(request: Request) -> InboundAuthResult:
    secret = os.getenv(PROXY_SECRET_ENV)
    if not secret:
        return InboundAuthResult(False, "trusted_proxy_not_configured")

    caller_header = os.getenv(PROXY_CALLER_HEADER_ENV, DEFAULT_CALLER_HEADER)
    sig_header = os.getenv(PROXY_SIGNATURE_HEADER_ENV, DEFAULT_SIGNATURE_HEADER)
    ts_header = os.getenv(PROXY_TIMESTAMP_HEADER_ENV, DEFAULT_TIMESTAMP_HEADER)

    caller = request.headers.get(caller_header, "").strip()
    signature = request.headers.get(sig_header, "").strip()
    timestamp = request.headers.get(ts_header, "").strip()
    if not caller or not signature or not timestamp:
        return InboundAuthResult(False, "trusted_proxy_headers_missing")

    try:
        ts_value = int(timestamp)
    except ValueError:
        return InboundAuthResult(False, "trusted_proxy_timestamp_invalid")
    if abs(int(time.time()) - ts_value) > MAX_PROXY_CLOCK_SKEW_SECONDS:
        return InboundAuthResult(False, "trusted_proxy_timestamp_stale")

    path_with_query = request.url.path
    if request.url.query:
        path_with_query = f"{path_with_query}?{request.url.query}"
    message = f"{timestamp}\n{caller}\n{request.method.upper()}\n{path_with_query}"
    expected = hmac.new(
        secret.encode("utf-8"), message.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(signature, expected):
        return InboundAuthResult(False, "trusted_proxy_signature_invalid")

    return InboundAuthResult(True, "trusted_proxy_hmac", caller_id=caller)


def authorize_inbound_http(
    request: Request | None,
    *,
    provider_type: str | None,
    configured_host: str | None,
    allow_oauth_callback: bool = True,
) -> InboundAuthResult:
    if request is None:
        return InboundAuthResult(True, "non_http_transport")
    if request.url.path in HEALTH_PATHS:
        return InboundAuthResult(True, "health")
    if allow_oauth_callback and request.url.path in OAUTH_CALLBACK_PATHS:
        return InboundAuthResult(True, "oauth_callback_state_validated_later")
    if is_allow_unauth_http_enabled():
        logger.warning(
            "MCP_ALLOW_UNAUTH_HTTP is enabled; unauthenticated HTTP is allowed"
        )
        return InboundAuthResult(True, "explicit_unauth_http_opt_in")

    proxy_result = verify_trusted_proxy_hmac(request)
    if proxy_result.allowed:
        return proxy_result

    static_bearer_result = verify_static_bearer(request)
    if static_bearer_result.allowed:
        return static_bearer_result

    bearer = extract_bearer_token(request)
    if provider_type == "openbridge" and is_openbridge_refresh_token(bearer):
        return InboundAuthResult(
            True,
            "openbridge_bearer",
            token_fingerprint=token_fingerprint(bearer or ""),
        )
    if provider_type == "kuudo" and bearer:
        return InboundAuthResult(
            True,
            "kuudo_bearer",
        )
    if provider_type == "direct" and request_is_loopback(request, configured_host):
        return InboundAuthResult(True, "direct_loopback")

    return InboundAuthResult(False, "caller_auth_required")


def get_provider_type(auth_manager: Any) -> str | None:
    provider = getattr(auth_manager, "provider", None) if auth_manager else None
    return getattr(provider, "provider_type", None) if provider else None


class InboundHTTPAuthMiddleware(Middleware):
    def __init__(self, auth_manager: Any, configured_host: str | None):
        super().__init__()
        self.auth_manager = auth_manager
        self.configured_host = configured_host
        get_static_bearer_token()

    def _authorize_tool_call(
        self, context: MiddlewareContext
    ) -> tuple[Request | None, InboundAuthResult]:
        request = None
        if context.fastmcp_context:
            request_ctx = getattr(context.fastmcp_context, "request_context", None)
            request = getattr(request_ctx, "request", None) if request_ctx else None
        if request is None:
            try:
                request = get_http_request()
            except RuntimeError:
                request = None

        result = authorize_inbound_http(
            request,
            provider_type=get_provider_type(self.auth_manager),
            configured_host=self.configured_host,
        )
        if not result.allowed:
            raise ToolError(AUTH_REQUIRED_MESSAGE)
        return request, result

    async def _call_authorized(
        self, context: MiddlewareContext, call_next: Any
    ) -> Any:
        request, result = self._authorize_tool_call(context)
        provider = getattr(self.auth_manager, "provider", None)
        bearer = extract_bearer_token(request) if request is not None else None
        if result.reason != "kuudo_bearer" or not bearer:
            return await call_next(context)

        api_key_context_token = provider.set_current_api_key(bearer)
        tenant_context_token = bind_request_tenant_fingerprint(
            provider.session_api_key_fingerprint(bearer)
        )
        try:
            return await call_next(context)
        finally:
            reset_request_tenant_token(tenant_context_token)
            provider.reset_current_api_key(api_key_context_token)
            set_state_reset_reason(None)

    async def on_request(self, context: MiddlewareContext, call_next: Any) -> Any:
        method = getattr(context, "method", None)
        if method == "tools/call":
            return await self._call_authorized(context, call_next)
        return await call_next(context)

    async def on_call_tool(self, context: MiddlewareContext, call_next: Any) -> Any:
        return await self._call_authorized(context, call_next)


def create_inbound_http_auth_middleware(
    auth_manager: Any, configured_host: str | None
) -> InboundHTTPAuthMiddleware:
    return InboundHTTPAuthMiddleware(auth_manager, configured_host)


def _is_tools_call_payload(payload: Any) -> bool:
    if isinstance(payload, dict):
        return payload.get("method") == "tools/call"
    if isinstance(payload, list):
        return any(
            isinstance(item, dict) and item.get("method") == "tools/call"
            for item in payload
        )
    return False


def _tool_name_from_payload(payload: Any) -> str | None:
    if isinstance(payload, dict):
        params = payload.get("params")
        if isinstance(params, dict):
            name = params.get("name")
            return str(name) if name else None
    return None


def _jsonrpc_id_from_payload(payload: Any) -> Any:
    return payload.get("id") if isinstance(payload, dict) else None


def _auth_error_event(payload: Any) -> bytes:
    tool_name = _tool_name_from_payload(payload)
    envelope = build_envelope_from_exception(
        AuthenticationError(AUTH_REQUIRED_MESSAGE),
        tool_name=tool_name,
    )
    envelope_text = envelope_to_json(envelope)
    response = {
        "jsonrpc": "2.0",
        "id": _jsonrpc_id_from_payload(payload),
        "result": {
            "isError": True,
            "content": [{"type": "text", "text": envelope_text}],
        },
    }
    data = json.dumps(response, ensure_ascii=True, separators=(",", ":"))
    return f"event: message\ndata: {data}\n\n".encode("utf-8")


class InboundHTTPAuthASGIMiddleware:
    """Gate HTTP tools/call requests before FastMCP worker dispatch."""

    def __init__(self, app: Any, auth_manager: Any, configured_host: str | None):
        self.app = app
        self.auth_manager = auth_manager
        self.configured_host = configured_host
        get_static_bearer_token()

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if (
            scope.get("type") != "http"
            or scope.get("method") != "POST"
            or scope.get("path") != "/mcp"
        ):
            await self.app(scope, receive, send)
            return

        body = b""
        more_body = True
        while more_body:
            message = await receive()
            if message.get("type") != "http.request":
                continue
            body += message.get("body", b"")
            more_body = bool(message.get("more_body", False))

        sent_body = False

        async def replay_receive() -> dict[str, Any]:
            nonlocal sent_body
            if not sent_body:
                sent_body = True
                return {
                    "type": "http.request",
                    "body": body,
                    "more_body": False,
                }
            return await receive()

        try:
            payload = json.loads(body.decode("utf-8")) if body else None
        except (UnicodeDecodeError, json.JSONDecodeError):
            await self.app(scope, replay_receive, send)
            return

        if not _is_tools_call_payload(payload):
            await self.app(scope, replay_receive, send)
            return

        request = Request(scope)
        result = authorize_inbound_http(
            request,
            provider_type=get_provider_type(self.auth_manager),
            configured_host=self.configured_host,
        )
        if result.allowed:
            await self.app(scope, replay_receive, send)
            return

        response = Response(
            _auth_error_event(payload),
            status_code=200,
            media_type="text/event-stream",
        )
        await response(scope, receive, send)


def create_inbound_http_auth_asgi_middleware(
    auth_manager: Any, configured_host: str | None
) -> StarletteMiddleware:
    return StarletteMiddleware(
        InboundHTTPAuthASGIMiddleware,
        auth_manager=auth_manager,
        configured_host=configured_host,
    )
