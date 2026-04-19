"""Tests for the dedicated session-scope probe tool and tightened
tool descriptions.

This file pins the third iteration of bug.md Issue 2:

  * A new ``get_session_state`` tool returns ``{session_present,
    state_scope, state_reason}`` with no side effects. It is the
    documented "call this once per block to learn the transport
    scope" entry point so agents do not need to call a stateful
    tool just to probe.

  * The 5 stateful surface tools (``set_context``,
    ``set_active_identity``, ``set_active_profile``, ``set_region``,
    ``clear_active_profile``) plus ``get_session_state`` carry the
    enumerated ``state_reason`` values, the one-sentence
    re-establishment rule, and a ``token_swapped`` subtlety note in
    their descriptions.

  * The ``execute`` meta-tool description references
    ``get_session_state`` as the probe and carries the same
    one-sentence rule.

Per design (verified with the client): we are NOT adding the three
state fields to ``SetProfileResponse``, ``ClearProfileResponse``, or
``SetRegionResponse``. The probe lives in one place; pure data
responses stay clean.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import pytest

from amazon_ads_mcp.models.builtin_responses import GetSessionStateResponse


class FakeFastMCPContext:
    """Minimal FastMCP context double — see test_session_scope_signaling.py."""

    def __init__(self, with_session: bool = True):
        self.request_context = object() if with_session else None
        self._state: dict = {}

    async def get_state(self, key):
        return self._state.get(key)

    async def set_state(self, key, value):
        self._state[key] = value


@pytest.fixture(autouse=True)
def _reset_session_reset_reason():
    """Each test starts with a clean ``state_reset_reason`` ContextVar."""
    from amazon_ads_mcp.auth.session_state import set_state_reset_reason

    set_state_reset_reason(None)
    yield
    set_state_reset_reason(None)


# ---------------------------------------------------------------------------
# 1. GetSessionStateResponse model
# ---------------------------------------------------------------------------


def test_get_session_state_response_model_shape():
    """Exactly three fields, all required (no padding from other domains)."""
    response = GetSessionStateResponse(
        session_present=True,
        state_scope="session",
        state_reason=None,
    )
    assert response.session_present is True
    assert response.state_scope == "session"
    assert response.state_reason is None

    fields = set(response.model_dump().keys())
    assert fields == {"session_present", "state_scope", "state_reason"}


def test_get_session_state_response_state_reason_optional():
    """``state_reason`` defaults to ``None`` so the happy-path call site
    does not need to pass it explicitly."""
    response = GetSessionStateResponse(session_present=True, state_scope="session")
    assert response.state_reason is None


# ---------------------------------------------------------------------------
# 2. _get_session_state_impl behavior — fresh, after-set, after-swap
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_session_state_fresh_block_with_session():
    """Verification point #1: ``get_session_state`` reports the
    transport's natural scope before any setup runs in the block."""
    from amazon_ads_mcp.server.builtin_tools import _get_session_state_impl

    ctx = FakeFastMCPContext(with_session=True)
    response = await _get_session_state_impl(ctx)

    assert isinstance(response, GetSessionStateResponse)
    assert response.session_present is True
    assert response.state_scope == "session"
    assert response.state_reason is None


@pytest.mark.asyncio
async def test_get_session_state_fresh_block_no_session():
    """A request-scoped transport reports ``"request"`` /
    ``"no_mcp_session"`` even on a fresh block."""
    from amazon_ads_mcp.server.builtin_tools import _get_session_state_impl

    ctx = FakeFastMCPContext(with_session=False)
    response = await _get_session_state_impl(ctx)

    assert response.session_present is False
    assert response.state_scope == "request"
    assert response.state_reason == "no_mcp_session"


@pytest.mark.asyncio
async def test_get_session_state_after_set_context_reports_session_scope(monkeypatch):
    """Verification point #2: after ``set_context`` succeeds in this
    block, ``get_session_state`` in a follow-up call still reports
    ``state_scope == 'session'`` — i.e. the probe reads live state,
    not a stale cached value."""
    from amazon_ads_mcp.models import Identity, SetActiveIdentityResponse
    from amazon_ads_mcp.server.builtin_tools import (
        _get_session_state_impl,
        _set_context_impl,
    )
    from amazon_ads_mcp.tools import identity as identity_tools
    from amazon_ads_mcp.tools import profile as profile_tools
    from amazon_ads_mcp.tools import region as region_tools

    test_identity = Identity(id="id-1", type="remote", attributes={"name": "Test"})
    monkeypatch.setattr(
        identity_tools,
        "set_active_identity",
        AsyncMock(
            return_value=SetActiveIdentityResponse(
                success=True, identity=test_identity, credentials_loaded=True
            )
        ),
    )
    monkeypatch.setattr(
        identity_tools, "get_active_identity", AsyncMock(return_value=test_identity)
    )
    monkeypatch.setattr(
        region_tools, "get_region", AsyncMock(return_value={"region": "na"})
    )
    monkeypatch.setattr(
        profile_tools, "get_active_profile", AsyncMock(return_value={"profile_id": "p1"})
    )

    ctx = FakeFastMCPContext(with_session=True)
    set_response = await _set_context_impl(ctx, identity_id="id-1")
    assert set_response.success is True

    probe_response = await _get_session_state_impl(ctx)
    assert probe_response.session_present is True
    assert probe_response.state_scope == "session"
    assert probe_response.state_reason is None


@pytest.mark.asyncio
async def test_get_session_state_after_token_swap_reports_reason():
    """When the middleware just cleared tenant state due to a token
    swap, ``get_session_state`` surfaces ``state_reason='token_swapped'``
    even though the transport remains session-capable."""
    from amazon_ads_mcp.auth.session_state import set_state_reset_reason
    from amazon_ads_mcp.server.builtin_tools import _get_session_state_impl

    ctx = FakeFastMCPContext(with_session=True)
    set_state_reset_reason("token_swapped")

    response = await _get_session_state_impl(ctx)
    assert response.session_present is True
    assert response.state_scope == "session"
    assert response.state_reason == "token_swapped"


@pytest.mark.asyncio
async def test_get_session_state_no_side_effects(monkeypatch):
    """The probe must not mutate ContextVars or call any setter/getter
    on the auth manager. We assert by spying on every state mutator."""
    from amazon_ads_mcp.auth import session_state
    from amazon_ads_mcp.server.builtin_tools import _get_session_state_impl

    forbidden = [
        "set_active_identity",
        "set_active_credentials",
        "set_active_profiles",
        "set_refresh_token_override",
        "set_last_seen_token_fingerprint",
        "set_state_reset_reason",
    ]
    for name in forbidden:
        original = getattr(session_state, name)

        def _trap(*args, _name=name, **kwargs):
            raise AssertionError(
                f"_get_session_state_impl must not call {_name}; "
                "it is a read-only probe"
            )

        monkeypatch.setattr(session_state, name, _trap)
        # Restore via monkeypatch's automatic teardown
        del original

    ctx = FakeFastMCPContext(with_session=True)
    await _get_session_state_impl(ctx)


# ---------------------------------------------------------------------------
# 3. Tool descriptions carry the rule + enumerated reasons
# ---------------------------------------------------------------------------


async def _collect_descriptions() -> dict[str, str]:
    """Boot a FastMCP server, register builtin tools, return the
    ``{tool_name: description}`` mapping for the tools we care about."""
    from fastmcp import FastMCP

    from amazon_ads_mcp.server.builtin_tools import (
        register_identity_tools,
        register_profile_tools,
        register_region_tools,
    )

    server = FastMCP("test-descriptions")
    await register_identity_tools(server)
    await register_profile_tools(server)
    await register_region_tools(server)

    tools = await server.list_tools()
    return {tool.name: tool.description or "" for tool in tools}


THE_RULE = (
    "Re-establish context before the next tool call iff "
    "`state_scope == 'request'` or `state_reason` is not null."
)

ENUMERATED_REASONS = ('"no_mcp_session"', '"token_swapped"', '"bridge_unavailable"')


@pytest.mark.asyncio
async def test_set_context_description_carries_rule_and_reasons():
    descriptions = await _collect_descriptions()

    desc = descriptions["set_context"]
    assert THE_RULE in desc, (
        "set_context description must carry the verbatim "
        "re-establishment rule so agents can grep for it"
    )
    for reason in ENUMERATED_REASONS:
        assert reason in desc, (
            f"set_context description must enumerate {reason}"
        )
    assert "get_session_state" in desc


@pytest.mark.asyncio
async def test_set_active_identity_description_carries_rule():
    descriptions = await _collect_descriptions()
    desc = descriptions["set_active_identity"]
    assert THE_RULE in desc
    assert "get_session_state" in desc


@pytest.mark.asyncio
async def test_set_active_profile_description_carries_rule():
    descriptions = await _collect_descriptions()
    desc = descriptions["set_active_profile"]
    assert THE_RULE in desc
    assert "get_session_state" in desc


@pytest.mark.asyncio
async def test_set_region_description_carries_rule():
    descriptions = await _collect_descriptions()
    desc = descriptions["set_region"]
    assert THE_RULE in desc
    assert "get_session_state" in desc


@pytest.mark.asyncio
async def test_clear_active_profile_description_carries_rule():
    descriptions = await _collect_descriptions()
    desc = descriptions["clear_active_profile"]
    assert THE_RULE in desc
    assert "get_session_state" in desc


@pytest.mark.asyncio
async def test_get_session_state_description_carries_rule_and_reasons():
    descriptions = await _collect_descriptions()
    desc = descriptions["get_session_state"]
    assert THE_RULE in desc
    for reason in ENUMERATED_REASONS:
        assert reason in desc
    # Token-swap subtlety call-out
    assert "token_swapped" in desc and "session" in desc


@pytest.mark.asyncio
async def test_get_session_state_description_calls_out_token_swap_subtlety():
    """The doc must explicitly note that ``state_scope`` can be
    ``"session"`` while ``state_reason`` is ``"token_swapped"`` — the
    one case where scope alone misleads an agent."""
    descriptions = await _collect_descriptions()
    desc = descriptions["get_session_state"]
    # We don't pin exact wording, just assert both halves of the
    # subtlety appear so an agent reading the description sees them
    # together.
    assert "token_swapped" in desc
    assert "rare" in desc.lower() or "subtle" in desc.lower() or "edge" in desc.lower()


# ---------------------------------------------------------------------------
# 4. EXECUTE_DESCRIPTION carries the probe reference + rule
# ---------------------------------------------------------------------------


def test_execute_description_references_get_session_state():
    """Verification point #3: the execute meta-tool description must
    point agents at ``get_session_state`` as the probe."""
    from amazon_ads_mcp.server.code_mode import EXECUTE_DESCRIPTION

    assert "get_session_state" in EXECUTE_DESCRIPTION


def test_execute_description_carries_the_rule():
    from amazon_ads_mcp.server.code_mode import EXECUTE_DESCRIPTION

    assert THE_RULE in EXECUTE_DESCRIPTION


def test_execute_description_states_one_probe_per_block():
    """The doc must teach the right frequency: one probe per block,
    not per call."""
    from amazon_ads_mcp.server.code_mode import EXECUTE_DESCRIPTION

    text = EXECUTE_DESCRIPTION.lower()
    assert "once per block" in text or "one probe per block" in text


# ---------------------------------------------------------------------------
# 5. We did NOT pollute pure-data response models
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "model_path",
    [
        "amazon_ads_mcp.models.builtin_responses.SetProfileResponse",
        "amazon_ads_mcp.models.builtin_responses.ClearProfileResponse",
        "amazon_ads_mcp.models.builtin_responses.SetRegionResponse",
        "amazon_ads_mcp.models.builtin_responses.ListReportFieldsResponse",
    ],
)
def test_pure_data_responses_do_not_carry_state_fields(model_path: str):
    """Per the contract decision: state fields live on probe tools and
    setter responses that already carry them. Other responses stay
    clean — no schema bloat, no misleading "this could differ per
    tool" inference."""
    import importlib

    module_path, class_name = model_path.rsplit(".", 1)
    module = importlib.import_module(module_path)
    model_cls: Any = getattr(module, class_name)

    field_names = set(model_cls.model_fields.keys())
    for forbidden in ("session_present", "state_scope", "state_reason"):
        assert forbidden not in field_names, (
            f"{class_name} should NOT carry {forbidden}; "
            "pure-data responses must stay clean per the agreed contract"
        )
