"""Unit tests for usage_context()/tenant_key() (Task 22 ruling #4).

Not skipif-guarded: ``amazon_ads_mcp.metering.context`` has no dependency
on ``mcp_outbound_metering`` -- only on this repo's own auth/session-state
modules -- so it is tested on every supported Python version, same
rationale as ``test_compat_guard.py``/``test_normalizer.py``/
``test_attribution.py``. Relies on ``tests/conftest.py``'s autouse
``mock_env_vars`` (AUTH_METHOD=direct with test credentials) and
``_reset_session_state`` fixtures for isolation between tests.
"""

from __future__ import annotations

from amazon_ads_mcp.auth.manager import get_auth_manager
from amazon_ads_mcp.auth.session_state import set_active_identity
from amazon_ads_mcp.metering.attribution import tool_name_scope
from amazon_ads_mcp.metering.context import tenant_key, usage_context
from amazon_ads_mcp.models import Identity


def test_usage_context_allowlist_keys_only() -> None:
    dims = usage_context()
    assert set(dims) == {"identity_id", "profile_id", "region", "auth_method", "tool_name"}


def test_usage_context_with_no_active_identity_is_all_none_but_present() -> None:
    dims = usage_context()
    assert dims["identity_id"] is None
    assert dims["tool_name"] is None
    # auth_method comes from the configured provider even with no active
    # identity -- mock_env_vars configures AUTH_METHOD=direct.
    assert dims["auth_method"] == "direct"


def test_usage_context_reflects_active_identity() -> None:
    identity = Identity(id="identity-123", attributes={"region": "eu"})
    set_active_identity(identity)
    dims = usage_context()
    assert dims["identity_id"] == "identity-123"


def test_tenant_key_matches_identity_id_dimension() -> None:
    identity = Identity(id="identity-456", attributes={})
    set_active_identity(identity)
    assert tenant_key() == "identity-456"
    assert tenant_key() == usage_context()["identity_id"]


def test_tenant_key_none_without_active_identity() -> None:
    assert tenant_key() is None


def test_usage_context_reflects_active_profile_id() -> None:
    identity = Identity(id="identity-789", attributes={})
    set_active_identity(identity)
    get_auth_manager().set_active_profile_id("profile-abc")
    dims = usage_context()
    assert dims["profile_id"] == "profile-abc"


def test_usage_context_reflects_tool_name_scope() -> None:
    assert usage_context()["tool_name"] is None
    with tool_name_scope("search_profiles"):
        assert usage_context()["tool_name"] == "search_profiles"
    assert usage_context()["tool_name"] is None


def test_usage_context_auth_method_reflects_provider_type() -> None:
    assert usage_context()["auth_method"] == get_auth_manager().provider.provider_type


def test_usage_context_region_defaults_to_none_without_routing_state() -> None:
    # _ROUTING_STATE_VAR defaults to {} (utils/http_client.py) until a real
    # request runs `_inject_headers`'s region-routing block; before that,
    # region is None -- not a KeyError, not an empty-dict dimension value.
    dims = usage_context()
    assert dims["region"] is None
