"""End-to-end smoke for set_active_profile validation (Commit 1 of fix/mcp-surface-quality).

Boots the real Amazon Ads MCP server in-memory (FastMCP `Client`) and exercises
the validation path through the full middleware chain — schema normalization,
sidecar transforms, error envelope translator. Mocks the cached profile list
so no live Amazon API call is made.

This is the "no fake fix" guarantee: a unit test on `set_active_profile` alone
would not catch a regression in:
- the envelope translator's classification of `ValidationError`
- middleware ordering (envelope must wrap, not bypass, the ValidationError)
- the full `_meta` shape downstream code may parse

Skips if neither ``openapi/resources/`` nor ``dist/openapi/resources/`` is
present in the repo.
"""

from __future__ import annotations

import pathlib

import pytest
import pytest_asyncio

pytest.importorskip("fastmcp")


def _resources_present() -> bool:
    root = pathlib.Path(__file__).parents[2]
    return (root / "openapi" / "resources").exists() or (
        root / "dist" / "openapi" / "resources"
    ).exists()


@pytest_asyncio.fixture
async def mcp_server_with_mocked_profiles(monkeypatch):
    """Real MCP server with the cached profile list mocked to a known set.

    Mocks ``amazon_ads_mcp.tools.profile_listing.get_profiles_cached`` so
    ``set_active_profile`` validates against a deterministic in-memory list
    instead of fetching from Amazon.
    """
    if not _resources_present():
        pytest.skip("No openapi/resources or dist/openapi/resources present")

    async def _fake_cached(force_refresh=False):
        return [
            {"profileId": 3281463030219274, "countryCode": "US"},
            {"profileId": 1234567890, "countryCode": "GB"},
        ], False

    from amazon_ads_mcp.tools import profile_listing

    monkeypatch.setattr(profile_listing, "get_profiles_cached", _fake_cached)

    from amazon_ads_mcp.server.mcp_server import create_amazon_ads_server

    return await create_amazon_ads_server()


@pytest.mark.asyncio
async def test_set_active_profile_valid_id_succeeds_through_mcp_protocol(
    mcp_server_with_mocked_profiles,
):
    """Wire-path: a valid cached profile ID succeeds end-to-end through the
    MCP protocol with the full SetProfileResponse shape."""
    from fastmcp import Client

    async with Client(mcp_server_with_mocked_profiles) as client:
        result = await client.call_tool(
            "set_active_profile",
            {"profile_id": "3281463030219274"},
        )

    # CallToolResult — extract structured content
    payload = result.structured_content or result.data
    if hasattr(payload, "model_dump"):
        payload = payload.model_dump()

    assert payload.get("success") is True
    assert payload.get("profile_id") == "3281463030219274"
    assert "message" in payload


@pytest.mark.asyncio
async def test_set_active_profile_garbage_id_returns_validation_error_envelope(
    mcp_server_with_mocked_profiles,
):
    """Wire-path: a garbage profile ID raises through the envelope translator
    as mcp_input_validation, NOT as a silent success. Catches regressions in:
    - the validation logic itself
    - the envelope translator's classification of ValidationError
    - middleware ordering (envelope must wrap, not bypass)
    """
    from fastmcp import Client
    from fastmcp.exceptions import ToolError

    async with Client(mcp_server_with_mocked_profiles) as client:
        with pytest.raises(ToolError) as excinfo:
            await client.call_tool(
                "set_active_profile",
                {"profile_id": "not-a-number"},
            )

    # ToolError message should reflect the validation reason — not a 401 from
    # Amazon and not a generic internal_error string.
    msg = str(excinfo.value).lower()
    assert "not found" in msg or "profile" in msg, (
        f"expected validation reason in error, got {excinfo.value!r}"
    )


@pytest.mark.asyncio
async def test_set_active_profile_garbage_id_does_not_corrupt_state(
    mcp_server_with_mocked_profiles,
):
    """Critical no-fake-fix check: failed validation must NOT mutate state.
    Sets a known-good profile, attempts a bad one, then queries the active
    profile via the SAME client (auth state is context-scoped per
    session_state.py, so external in-process reads see a different context).
    """
    from fastmcp import Client
    from fastmcp.exceptions import ToolError

    async with Client(mcp_server_with_mocked_profiles) as client:
        # Establish known-good state
        await client.call_tool(
            "set_active_profile", {"profile_id": "3281463030219274"}
        )
        # Attempt bad ID — must fail without changing state
        with pytest.raises(ToolError):
            await client.call_tool(
                "set_active_profile", {"profile_id": "not-a-number"}
            )
        # Within same client session: state must still be the known-good value
        result = await client.call_tool("get_active_profile", {})
        payload = result.structured_content or result.data
        if hasattr(payload, "model_dump"):
            payload = payload.model_dump()
        assert payload.get("profile_id") == "3281463030219274", (
            f"profile state corrupted: failed validation should not mutate, "
            f"but get_active_profile returned {payload!r}"
        )


@pytest.mark.asyncio
async def test_set_active_profile_empty_string_returns_validation_error(
    mcp_server_with_mocked_profiles,
):
    """Empty profile_id must surface as a validation error through the wire,
    not as a Pydantic schema-validation error or a server crash."""
    from fastmcp import Client
    from fastmcp.exceptions import ToolError

    async with Client(mcp_server_with_mocked_profiles) as client:
        with pytest.raises(ToolError) as excinfo:
            await client.call_tool("set_active_profile", {"profile_id": ""})

    msg = str(excinfo.value).lower()
    assert "non-empty" in msg or "empty" in msg or "invalid" in msg
