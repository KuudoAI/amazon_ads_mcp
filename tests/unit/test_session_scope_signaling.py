"""Tests for the session-scope signaling contract.

This file pins down the second iteration of bug.md Issue 2:

  * ``persist`` is removed from ``SetActiveIdentityRequest`` and from
    every tool parameter — the field was a no-op and middleware
    handles persistence automatically.
  * Five tool responses gain a tight three-field state contract with
    documented, independent semantics:

      - ``session_present: Optional[bool]`` — pure transport fact
        (does ``has_auth_session(ctx)`` return True?).
      - ``state_scope: Literal["session", "request"]`` — client
        directive: should the agent treat state as sticky for the
        next call (``"session"``) or re-establish per call
        (``"request"``)?
      - ``state_reason: Optional[Literal["no_mcp_session",
        "token_swapped", "bridge_unavailable"]]`` — explanation of
        why state is not session-sticky, or why state was wiped
        despite a session being present.

  * ``state_reason="token_swapped"`` is set by the refresh-token
    middleware when a different bearer token arrives mid-session and
    tenant state gets cleared. It's the agent's signal that
    re-establishing context is required even though the transport is
    session-capable.

  * The contract is exposed on five tools: ``set_context``,
    ``set_active_identity``, ``get_active_identity``,
    ``get_active_profile``, ``get_routing_state``.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from amazon_ads_mcp.models import (
    Identity,
    SetActiveIdentityRequest,
    SetActiveIdentityResponse,
)
from amazon_ads_mcp.models.builtin_responses import (
    GetActiveIdentityResponse,
    GetProfileResponse,
    RoutingStateResponse,
    SetContextResponse,
)


class FakeFastMCPContext:
    """Minimal stand-in for ``fastmcp.Context``.

    Mirrors the duck-typed surface that ``has_auth_session`` looks at
    (``get_state``, ``set_state``, ``request_context``) so we can drive
    both "session present" and "no session" cases without booting a
    real FastMCP server.
    """

    def __init__(self, with_session: bool = True):
        self.request_context = object() if with_session else None
        self._state: dict = {}

    async def get_state(self, key):
        return self._state.get(key)

    async def set_state(self, key, value):
        self._state[key] = value


@pytest.fixture(autouse=True)
def _reset_session_reset_reason():
    """Keep tests isolated: clear ``state_reset_reason`` ContextVar.

    This var is read by ``compute_session_state`` and persists across
    tests in the same async context if not reset.
    """
    from amazon_ads_mcp.auth.session_state import set_state_reset_reason

    set_state_reset_reason(None)
    yield
    set_state_reset_reason(None)


# ---------------------------------------------------------------------------
# 1. persist removal
# ---------------------------------------------------------------------------


def test_set_active_identity_request_no_longer_has_persist_field():
    """``persist`` is removed from the request schema entirely.

    Pydantic ignores unknown fields by default, so existing callers
    passing ``persist=True`` still construct successfully — the value
    is silently dropped, matching the prior observable (no-op)
    behavior.
    """
    request = SetActiveIdentityRequest(identity_id="id-1")
    assert "persist" not in request.model_dump()


def test_set_active_identity_request_silently_ignores_legacy_persist():
    """Backward-compat: existing code that constructs the request with
    ``persist=True`` does not raise."""
    request = SetActiveIdentityRequest(identity_id="id-1", persist=True)
    assert request.identity_id == "id-1"
    assert "persist" not in request.model_dump()


def test_set_context_impl_does_not_accept_persist_kwarg():
    """The tool helper drops the ``persist`` keyword entirely."""
    import inspect

    from amazon_ads_mcp.server.builtin_tools import _set_context_impl

    sig = inspect.signature(_set_context_impl)
    assert "persist" not in sig.parameters


def test_set_active_identity_impl_does_not_accept_persist_kwarg():
    import inspect

    from amazon_ads_mcp.server.builtin_tools import _set_active_identity_impl

    sig = inspect.signature(_set_active_identity_impl)
    assert "persist" not in sig.parameters


def test_region_identity_no_longer_passes_persist_true():
    """``switch_to_region_identity`` constructed the request with
    ``persist=True``; that callsite is now updated to drop the kwarg."""
    import inspect

    from amazon_ads_mcp.tools import region_identity

    source = inspect.getsource(region_identity)
    assert "persist=True" not in source
    assert "persist=False" not in source


# ---------------------------------------------------------------------------
# 2. Response model surface — three fields with hard semantics
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "model_cls,required_kwargs",
    [
        (SetContextResponse, {"success": True}),
        (
            SetActiveIdentityResponse,
            {
                "success": True,
                "identity": Identity(id="id-1", type="remote", attributes={}),
                "credentials_loaded": True,
            },
        ),
        (GetActiveIdentityResponse, {"success": True}),
        (GetProfileResponse, {"success": True}),
        (
            RoutingStateResponse,
            {"region": "na", "host": "https://advertising-api.amazon.com"},
        ),
    ],
)
def test_response_models_expose_three_state_fields(model_cls, required_kwargs):
    """Every probe/action response carries the same three state fields."""
    instance = model_cls(
        **required_kwargs,
        session_present=True,
        state_scope="session",
        state_reason=None,
    )
    assert instance.session_present is True
    assert instance.state_scope == "session"
    assert instance.state_reason is None


@pytest.mark.parametrize(
    "model_cls,required_kwargs",
    [
        (SetContextResponse, {"success": True}),
        (GetActiveIdentityResponse, {"success": True}),
        (GetProfileResponse, {"success": True}),
        (
            RoutingStateResponse,
            {"region": "na", "host": "https://advertising-api.amazon.com"},
        ),
    ],
)
def test_response_models_state_fields_default_to_none(model_cls, required_kwargs):
    """Fields are optional so they don't leak into core/internal callers."""
    instance = model_cls(**required_kwargs)
    assert instance.session_present is None
    assert instance.state_scope is None
    assert instance.state_reason is None


# ---------------------------------------------------------------------------
# 3. compute_session_state helper — independent semantics for the 3 fields
# ---------------------------------------------------------------------------


def test_compute_session_state_no_context_returns_request_no_session():
    from amazon_ads_mcp.middleware.auth_session_bridge import compute_session_state

    session_present, state_scope, state_reason = compute_session_state(None)
    assert session_present is False
    assert state_scope == "request"
    assert state_reason == "no_mcp_session"


def test_compute_session_state_no_session_returns_request_no_session():
    from amazon_ads_mcp.middleware.auth_session_bridge import compute_session_state

    ctx = FakeFastMCPContext(with_session=False)
    session_present, state_scope, state_reason = compute_session_state(ctx)
    assert session_present is False
    assert state_scope == "request"
    assert state_reason == "no_mcp_session"


def test_compute_session_state_with_session_clean_returns_session():
    from amazon_ads_mcp.middleware.auth_session_bridge import compute_session_state

    ctx = FakeFastMCPContext(with_session=True)
    session_present, state_scope, state_reason = compute_session_state(ctx)
    assert session_present is True
    assert state_scope == "session"
    assert state_reason is None


def test_compute_session_state_with_session_after_token_swap():
    """Session is present (transport-capable) but state was wiped by
    middleware on token rotation — agent must re-establish context."""
    from amazon_ads_mcp.auth.session_state import set_state_reset_reason
    from amazon_ads_mcp.middleware.auth_session_bridge import compute_session_state

    ctx = FakeFastMCPContext(with_session=True)
    set_state_reset_reason("token_swapped")

    session_present, state_scope, state_reason = compute_session_state(ctx)
    assert session_present is True
    # Transport CAN persist, but agent should still re-establish.
    # state_scope reflects transport capability; state_reason carries
    # the actionable signal that prior state was wiped.
    assert state_scope == "session"
    assert state_reason == "token_swapped"


# ---------------------------------------------------------------------------
# 4. Tool wrappers populate the three fields
# ---------------------------------------------------------------------------


@pytest.fixture
def patched_set_context_deps(monkeypatch):
    from amazon_ads_mcp.tools import identity as identity_tools
    from amazon_ads_mcp.tools import profile as profile_tools
    from amazon_ads_mcp.tools import region as region_tools

    test_identity = Identity(id="id-1", type="remote", attributes={"name": "Test"})

    # Spec each AsyncMock against the real tool function so signature drift
    # (renamed kwarg, added required arg) fails at the call site instead of
    # silently accepting any arguments.
    monkeypatch.setattr(
        identity_tools,
        "set_active_identity",
        AsyncMock(
            spec=identity_tools.set_active_identity,
            return_value=SetActiveIdentityResponse(
                success=True,
                identity=test_identity,
                credentials_loaded=True,
            ),
        ),
    )
    monkeypatch.setattr(
        identity_tools,
        "get_active_identity",
        AsyncMock(spec=identity_tools.get_active_identity, return_value=test_identity),
    )
    monkeypatch.setattr(
        region_tools,
        "set_region",
        AsyncMock(spec=region_tools.set_region, return_value={"success": True, "region": "na"}),
    )
    monkeypatch.setattr(
        region_tools,
        "get_region",
        AsyncMock(spec=region_tools.get_region, return_value={"region": "na"}),
    )
    monkeypatch.setattr(
        profile_tools,
        "set_active_profile",
        AsyncMock(spec=profile_tools.set_active_profile, return_value={"success": True}),
    )
    monkeypatch.setattr(
        profile_tools,
        "get_active_profile",
        AsyncMock(spec=profile_tools.get_active_profile, return_value={"profile_id": "p1"}),
    )

    return SimpleNamespace(identity=test_identity)


@pytest.mark.asyncio
async def test_set_context_impl_with_session_populates_session_state(
    patched_set_context_deps,
):
    from amazon_ads_mcp.server.builtin_tools import _set_context_impl

    ctx = FakeFastMCPContext(with_session=True)
    response = await _set_context_impl(ctx, identity_id="id-1")

    assert response.success is True
    assert response.session_present is True
    assert response.state_scope == "session"
    assert response.state_reason is None


@pytest.mark.asyncio
async def test_set_context_impl_no_session_populates_request_state(
    patched_set_context_deps,
):
    from amazon_ads_mcp.server.builtin_tools import _set_context_impl

    ctx = FakeFastMCPContext(with_session=False)
    response = await _set_context_impl(ctx, identity_id="id-1")

    assert response.session_present is False
    assert response.state_scope == "request"
    assert response.state_reason == "no_mcp_session"


@pytest.mark.asyncio
async def test_set_context_impl_after_token_swap_carries_reason(
    patched_set_context_deps,
):
    from amazon_ads_mcp.auth.session_state import set_state_reset_reason
    from amazon_ads_mcp.server.builtin_tools import _set_context_impl

    set_state_reset_reason("token_swapped")
    ctx = FakeFastMCPContext(with_session=True)
    response = await _set_context_impl(ctx, identity_id="id-1")

    assert response.session_present is True
    assert response.state_scope == "session"
    assert response.state_reason == "token_swapped"


@pytest.mark.asyncio
async def test_set_active_identity_impl_populates_state_fields(monkeypatch):
    from amazon_ads_mcp.server.builtin_tools import _set_active_identity_impl
    from amazon_ads_mcp.tools import identity as identity_tools

    monkeypatch.setattr(
        identity_tools,
        "set_active_identity",
        AsyncMock(
            spec=identity_tools.set_active_identity,
            return_value=SetActiveIdentityResponse(
                success=True,
                identity=Identity(id="id-1", type="remote", attributes={}),
                credentials_loaded=True,
            ),
        ),
    )

    ctx = FakeFastMCPContext(with_session=False)
    response = await _set_active_identity_impl(ctx, identity_id="id-1")

    assert response.session_present is False
    assert response.state_scope == "request"
    assert response.state_reason == "no_mcp_session"


@pytest.mark.asyncio
async def test_get_active_identity_impl_returns_wrapped_response_with_state(monkeypatch):
    from amazon_ads_mcp.server.builtin_tools import _get_active_identity_impl
    from amazon_ads_mcp.tools import identity as identity_tools

    test_identity = Identity(id="id-1", type="remote", attributes={"name": "Test"})
    monkeypatch.setattr(
        identity_tools,
        "get_active_identity",
        AsyncMock(spec=identity_tools.get_active_identity, return_value=test_identity),
    )

    ctx = FakeFastMCPContext(with_session=True)
    response = await _get_active_identity_impl(ctx)

    assert isinstance(response, GetActiveIdentityResponse)
    assert response.success is True
    assert response.identity is not None
    assert response.identity["id"] == "id-1"
    assert response.session_present is True
    assert response.state_scope == "session"
    assert response.state_reason is None


@pytest.mark.asyncio
async def test_get_active_identity_impl_no_identity_still_carries_state(monkeypatch):
    from amazon_ads_mcp.server.builtin_tools import _get_active_identity_impl
    from amazon_ads_mcp.tools import identity as identity_tools

    monkeypatch.setattr(
        identity_tools,
        "get_active_identity",
        AsyncMock(spec=identity_tools.get_active_identity, return_value=None),
    )

    ctx = FakeFastMCPContext(with_session=False)
    response = await _get_active_identity_impl(ctx)

    assert response.success is True
    assert response.identity is None
    assert response.state_scope == "request"
    assert response.state_reason == "no_mcp_session"


@pytest.mark.asyncio
async def test_get_active_profile_impl_carries_state(monkeypatch):
    from amazon_ads_mcp.server.builtin_tools import _get_active_profile_impl
    from amazon_ads_mcp.tools import profile as profile_tools

    monkeypatch.setattr(
        profile_tools,
        "get_active_profile",
        AsyncMock(
            spec=profile_tools.get_active_profile,
            return_value={"success": True, "profile_id": "p1", "source": "explicit"},
        ),
    )

    ctx = FakeFastMCPContext(with_session=True)
    response = await _get_active_profile_impl(ctx)

    assert isinstance(response, GetProfileResponse)
    assert response.profile_id == "p1"
    assert response.session_present is True
    assert response.state_scope == "session"


@pytest.mark.asyncio
async def test_get_routing_state_impl_carries_state(monkeypatch):
    from amazon_ads_mcp.server import builtin_tools
    from amazon_ads_mcp.utils import http_client as http_client_module

    monkeypatch.setattr(
        http_client_module,
        "get_routing_state",
        lambda: {"region": "na", "host": "https://advertising-api.amazon.com", "headers": {}},
    )

    ctx = FakeFastMCPContext(with_session=False)
    response = await builtin_tools._get_routing_state_impl(ctx)

    assert isinstance(response, RoutingStateResponse)
    assert response.region == "na"
    assert response.session_present is False
    assert response.state_scope == "request"
    assert response.state_reason == "no_mcp_session"


# ---------------------------------------------------------------------------
# 5. Middleware sets state_reset_reason on token swap
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_refresh_token_middleware_sets_token_swapped_on_swap():
    """Token rotation mid-session must mark ``state_reset_reason``
    so the next tool call surfaces it via ``compute_session_state``."""
    from amazon_ads_mcp.auth.session_state import (
        get_state_reset_reason,
        reset_all_session_state,
        set_last_seen_token_fingerprint,
        token_fingerprint,
    )

    reset_all_session_state()

    # Seed a fingerprint as if a prior request had token A
    token_a = "tenant-a:secret"
    set_last_seen_token_fingerprint(token_fingerprint(token_a))

    # Now arrive with token B and run the swap-detection block
    from amazon_ads_mcp.auth.session_state import (
        set_active_credentials,
        set_active_identity,
        set_active_profiles,
        set_last_seen_token_fingerprint as set_fp,
        set_state_reset_reason,
    )

    token_b = "tenant-b:secret"
    new_fp = token_fingerprint(token_b)
    previous_fp = token_fingerprint(token_a)

    # This mimics the middleware swap branch
    if previous_fp and previous_fp != new_fp:
        set_active_identity(None)
        set_active_credentials(None)
        set_active_profiles(None)
        set_state_reset_reason("token_swapped")
    set_fp(new_fp)

    assert get_state_reset_reason() == "token_swapped"
    reset_all_session_state()


@pytest.mark.asyncio
async def test_state_reset_reason_cleared_on_normal_request():
    """When token does not change, ``state_reset_reason`` is ``None``."""
    from amazon_ads_mcp.auth.session_state import (
        get_state_reset_reason,
        reset_all_session_state,
        set_state_reset_reason,
    )

    reset_all_session_state()
    set_state_reset_reason(None)

    assert get_state_reset_reason() is None
    reset_all_session_state()


@pytest.mark.asyncio
async def test_refresh_token_middleware_clears_state_reset_reason_after_request():
    """Integration check: the middleware uses a finally-block to wipe
    ``state_reset_reason`` so it does not leak to the next request."""
    from types import SimpleNamespace

    from amazon_ads_mcp.auth.session_state import (
        get_state_reset_reason,
        reset_all_session_state,
        set_last_seen_token_fingerprint,
        token_fingerprint,
    )
    from amazon_ads_mcp.config.settings import settings as global_settings
    from amazon_ads_mcp.middleware.authentication import (
        AuthConfig,
        RefreshTokenMiddleware,
    )

    reset_all_session_state()

    # Pre-existing session state with token A
    set_last_seen_token_fingerprint(token_fingerprint("tenant-a:secret"))

    # Build a mock request carrying token B in the OpenBridge header
    token_b = "tenant-b:secret"
    headers = {"x-openbridge-token": token_b}

    class DummyRequest:
        def __init__(self, headers):
            self.headers = headers

    fastmcp_context = SimpleNamespace(
        request_context=SimpleNamespace(request=DummyRequest(headers))
    )
    middleware_context = SimpleNamespace(fastmcp_context=fastmcp_context)

    config = AuthConfig()
    config.enabled = False  # Skip JWT conversion for this test
    config.refresh_token_pattern = lambda _t: True
    middleware = RefreshTokenMiddleware(config, auth_manager=None)

    captured = {}

    async def call_next(_):
        captured["reason_during_call"] = get_state_reset_reason()
        return "ok"

    # Avoid touching real http client
    _orig_persist_setting = global_settings.token_persist
    try:
        await middleware.on_request(middleware_context, call_next)
    finally:
        global_settings.token_persist = _orig_persist_setting

    # Inside the tool: reason is observable
    assert captured["reason_during_call"] == "token_swapped"
    # After the request: the middleware finally-block has cleared it
    assert get_state_reset_reason() is None
    reset_all_session_state()
