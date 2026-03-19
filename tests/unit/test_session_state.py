"""Tests for per-request session state using ContextVars.

Verifies that ContextVar-backed session state provides proper
isolation between concurrent async tasks, correct defaults,
and copy-on-write semantics for profiles.
"""

import asyncio

import pytest

from amazon_ads_mcp.auth.session_state import (
    get_active_credentials,
    get_active_identity,
    get_active_profiles,
    get_refresh_token_override,
    reset_session_state,
    set_active_credentials,
    set_active_identity,
    set_active_profiles,
    set_refresh_token_override,
)
from amazon_ads_mcp.models import AuthCredentials, Identity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_identity(id: str) -> Identity:
    """Create a minimal Identity for testing."""
    return Identity(id=id, type="test", attributes={"name": f"Test {id}"})


def _make_credentials(identity_id: str) -> AuthCredentials:
    """Create minimal AuthCredentials for testing."""
    from datetime import datetime, timezone

    return AuthCredentials(
        identity_id=identity_id,
        access_token=f"token-{identity_id}",
        expires_at=datetime(2099, 1, 1, tzinfo=timezone.utc),
        base_url="https://example.com",
        headers={},
    )


# ---------------------------------------------------------------------------
# Default values
# ---------------------------------------------------------------------------


class TestDefaults:
    """All ContextVars return safe defaults when unset."""

    def test_identity_default_is_none(self):
        assert get_active_identity() is None

    def test_credentials_default_is_none(self):
        assert get_active_credentials() is None

    def test_profiles_default_is_empty_dict(self):
        profiles = get_active_profiles()
        assert profiles == {}
        assert isinstance(profiles, dict)

    def test_refresh_token_override_default_is_none(self):
        assert get_refresh_token_override() is None


# ---------------------------------------------------------------------------
# Set / Get round-trip
# ---------------------------------------------------------------------------


class TestSetGet:
    """Basic set/get operations work correctly."""

    def test_set_and_get_identity(self):
        identity = _make_identity("test-1")
        set_active_identity(identity)
        assert get_active_identity() is identity

    def test_set_and_get_credentials(self):
        creds = _make_credentials("test-1")
        set_active_credentials(creds)
        assert get_active_credentials() is creds

    def test_set_and_get_profiles(self):
        profiles = {"id-1": "profile-100"}
        set_active_profiles(profiles)
        assert get_active_profiles() == {"id-1": "profile-100"}

    def test_set_and_get_refresh_token_override(self):
        set_refresh_token_override("my-token")
        assert get_refresh_token_override() == "my-token"

    def test_clear_by_setting_none(self):
        set_active_identity(_make_identity("x"))
        set_active_identity(None)
        assert get_active_identity() is None


# ---------------------------------------------------------------------------
# Reset
# ---------------------------------------------------------------------------


class TestReset:
    """reset_session_state() clears all vars."""

    def test_reset_clears_all(self):
        set_active_identity(_make_identity("x"))
        set_active_credentials(_make_credentials("x"))
        set_active_profiles({"x": "100"})
        set_refresh_token_override("tok")

        reset_session_state()

        assert get_active_identity() is None
        assert get_active_credentials() is None
        assert get_active_profiles() == {}
        assert get_refresh_token_override() is None


# ---------------------------------------------------------------------------
# Copy-on-write for profiles
# ---------------------------------------------------------------------------


class TestCopyOnWrite:
    """Mutating returned profiles dict doesn't affect stored state."""

    def test_mutating_returned_dict_is_safe(self):
        set_active_profiles({"a": "1"})
        returned = get_active_profiles()
        returned["b"] = "2"  # Mutate the returned dict

        # The stored value should be unchanged
        assert get_active_profiles() == {"a": "1"}

    def test_none_default_not_mutated(self):
        """get_active_profiles() returns a new empty dict each time when unset."""
        d1 = get_active_profiles()
        d1["x"] = "y"
        d2 = get_active_profiles()
        assert d2 == {}


# ---------------------------------------------------------------------------
# Concurrent task isolation
# ---------------------------------------------------------------------------


class TestTaskIsolation:
    """Two concurrent tasks see independent ContextVar state."""

    @pytest.mark.asyncio
    async def test_identity_isolation(self):
        """Two tasks set different identities, each sees only its own."""
        results = {}

        async def task_a():
            identity = _make_identity("task-a")
            set_active_identity(identity)
            # Yield to let task_b run
            await asyncio.sleep(0.01)
            results["a"] = get_active_identity()

        async def task_b():
            identity = _make_identity("task-b")
            set_active_identity(identity)
            await asyncio.sleep(0.01)
            results["b"] = get_active_identity()

        await asyncio.gather(task_a(), task_b())

        assert results["a"].id == "task-a"
        assert results["b"].id == "task-b"

    @pytest.mark.asyncio
    async def test_profiles_isolation(self):
        """Two tasks set different profiles, each sees only its own."""
        results = {}

        async def task_a():
            set_active_profiles({"id-a": "100"})
            await asyncio.sleep(0.01)
            results["a"] = get_active_profiles()

        async def task_b():
            set_active_profiles({"id-b": "200"})
            await asyncio.sleep(0.01)
            results["b"] = get_active_profiles()

        await asyncio.gather(task_a(), task_b())

        assert results["a"] == {"id-a": "100"}
        assert results["b"] == {"id-b": "200"}

    @pytest.mark.asyncio
    async def test_refresh_token_isolation(self):
        """Two tasks set different refresh tokens, each sees only its own."""
        results = {}

        async def task_a():
            set_refresh_token_override("token-a")
            await asyncio.sleep(0.01)
            results["a"] = get_refresh_token_override()

        async def task_b():
            set_refresh_token_override("token-b")
            await asyncio.sleep(0.01)
            results["b"] = get_refresh_token_override()

        await asyncio.gather(task_a(), task_b())

        assert results["a"] == "token-a"
        assert results["b"] == "token-b"

    @pytest.mark.asyncio
    async def test_child_task_inherits_parent_context(self):
        """Child tasks created via asyncio.create_task inherit parent ContextVars."""
        parent_identity = _make_identity("parent")
        set_active_identity(parent_identity)

        child_result = {}

        async def child():
            child_result["identity"] = get_active_identity()

        task = asyncio.create_task(child())
        await task

        assert child_result["identity"].id == "parent"
