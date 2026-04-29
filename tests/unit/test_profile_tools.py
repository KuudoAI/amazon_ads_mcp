from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from amazon_ads_mcp.tools import profile as profile_tools
from amazon_ads_mcp.utils.errors import ErrorCategory, ValidationError


# Note on test design: these tests deliberately use SimpleNamespace as a
# *whitelist* for AuthManager methods. Any access to a method NOT explicitly
# stubbed AttributeErrors immediately — stricter than spec=AuthManager. The
# inner MagicMock() stubs intentionally don't carry signature specs because
# spec'ing against AuthManager's unbound methods introduces a phantom `self`
# arg that breaks `assert_called_once_with(...)` on caller-supplied args.


def _mock_cached_profiles(monkeypatch, profile_ids):
    """Patch get_profiles_cached to return the given profile IDs (no live API)."""
    profiles = [{"profileId": int(pid) if pid.isdigit() else pid} for pid in profile_ids]

    async def _fake_cached(force_refresh=False):
        return profiles, False

    # Patch the import target — set_active_profile imports it lazily
    from amazon_ads_mcp.tools import profile_listing

    monkeypatch.setattr(profile_listing, "get_profiles_cached", _fake_cached)


def _mock_cached_profiles_full(monkeypatch, profiles):
    """Patch get_profiles_cached to return arbitrary full profile dicts.

    Use this when a test needs to inject ``accountInfo`` / ``countryCode``
    metadata to exercise F6's response enrichment.
    """

    async def _fake_cached(force_refresh=False):
        return profiles, False

    from amazon_ads_mcp.tools import profile_listing

    monkeypatch.setattr(profile_listing, "get_profiles_cached", _fake_cached)


@pytest.mark.asyncio
async def test_set_active_profile_valid_id(monkeypatch):
    """Regression: setting a valid cached profile ID still succeeds with the
    full SetProfileResponse shape (success, profile_id, message)."""
    manager = SimpleNamespace(set_active_profile_id=MagicMock())
    monkeypatch.setattr(profile_tools, "get_auth_manager", lambda: manager)
    _mock_cached_profiles(monkeypatch, ["123", "456"])

    result = await profile_tools.set_active_profile("123")

    assert result["success"] is True
    assert result["profile_id"] == "123"
    assert "message" in result
    manager.set_active_profile_id.assert_called_once_with("123")


@pytest.mark.asyncio
async def test_set_active_profile_empty_string_raises_validation_error(monkeypatch):
    """Empty profile_id must raise typed ValidationError, not silently accept."""
    manager = SimpleNamespace(set_active_profile_id=MagicMock())
    monkeypatch.setattr(profile_tools, "get_auth_manager", lambda: manager)

    with pytest.raises(ValidationError) as excinfo:
        await profile_tools.set_active_profile("")

    assert excinfo.value.category == ErrorCategory.VALIDATION
    assert "non-empty" in str(excinfo.value).lower()
    # Critical: no partial state — auth_manager.set_active_profile_id must NOT be called
    manager.set_active_profile_id.assert_not_called()


@pytest.mark.asyncio
async def test_set_active_profile_whitespace_only_raises(monkeypatch):
    """Whitespace-only is also empty for our purposes."""
    manager = SimpleNamespace(set_active_profile_id=MagicMock())
    monkeypatch.setattr(profile_tools, "get_auth_manager", lambda: manager)

    with pytest.raises(ValidationError):
        await profile_tools.set_active_profile("   ")
    manager.set_active_profile_id.assert_not_called()


@pytest.mark.asyncio
async def test_set_active_profile_garbage_string_raises(monkeypatch):
    """Garbage profile ID (not in cached list) must raise ValidationError
    with PROFILE_NOT_FOUND. Previously: silent success → 401s downstream."""
    manager = SimpleNamespace(set_active_profile_id=MagicMock())
    monkeypatch.setattr(profile_tools, "get_auth_manager", lambda: manager)
    _mock_cached_profiles(monkeypatch, ["3281463030219274", "1234567890"])

    with pytest.raises(ValidationError) as excinfo:
        await profile_tools.set_active_profile("not-a-number")

    assert excinfo.value.category == ErrorCategory.VALIDATION
    assert "not found" in str(excinfo.value).lower()
    manager.set_active_profile_id.assert_not_called()


@pytest.mark.asyncio
async def test_set_active_profile_numeric_but_unknown_raises(monkeypatch):
    """Numeric profile ID that isn't in the cached list must also be rejected."""
    manager = SimpleNamespace(set_active_profile_id=MagicMock())
    monkeypatch.setattr(profile_tools, "get_auth_manager", lambda: manager)
    _mock_cached_profiles(monkeypatch, ["3281463030219274"])

    with pytest.raises(ValidationError) as excinfo:
        await profile_tools.set_active_profile("99999999999")

    assert "not found" in str(excinfo.value).lower()
    manager.set_active_profile_id.assert_not_called()


@pytest.mark.asyncio
async def test_set_active_profile_did_you_mean_hint(monkeypatch):
    """A close-match profile ID surfaces a did_you_mean suggestion in details."""
    manager = SimpleNamespace(set_active_profile_id=MagicMock())
    monkeypatch.setattr(profile_tools, "get_auth_manager", lambda: manager)
    _mock_cached_profiles(monkeypatch, ["3281463030219274"])

    with pytest.raises(ValidationError) as excinfo:
        await profile_tools.set_active_profile("3281463030219275")  # off by 1

    err = excinfo.value
    hints = err.details.get("hints") if isinstance(err.details, dict) else None
    assert hints, f"expected did_you_mean hints, got {err.details!r}"
    assert any("3281463030219274" in s for h in hints for s in h.get("suggestions", []))


@pytest.mark.asyncio
async def test_set_active_profile_cache_failure_propagates(monkeypatch):
    """If the cached profile fetch raises (e.g. network down), the validation
    error should propagate cleanly — not get swallowed into a misleading 'profile
    not found' that masks the real cause."""
    manager = SimpleNamespace(set_active_profile_id=MagicMock())
    monkeypatch.setattr(profile_tools, "get_auth_manager", lambda: manager)

    async def _broken_cache(force_refresh=False):
        raise RuntimeError("upstream cache unreachable")

    from amazon_ads_mcp.tools import profile_listing

    monkeypatch.setattr(profile_listing, "get_profiles_cached", _broken_cache)

    with pytest.raises(RuntimeError) as excinfo:
        await profile_tools.set_active_profile("123")
    assert "cache unreachable" in str(excinfo.value)
    manager.set_active_profile_id.assert_not_called()


# ---------------------------------------------------------------------------
# F6: set_active_profile echoes resolved profile metadata
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_set_active_profile_echoes_profile_metadata(monkeypatch):
    """F6: response includes name, country_code, account_type from the cached
    profile so agents can confirm the marketplace without a follow-up
    get_active_profile call."""
    manager = SimpleNamespace(set_active_profile_id=MagicMock())
    monkeypatch.setattr(profile_tools, "get_auth_manager", lambda: manager)
    _mock_cached_profiles_full(monkeypatch, [
        {
            "profileId": 3194577320222553,
            "countryCode": "US",
            "accountInfo": {"name": "Solid Gold Pet", "type": "seller"},
        },
        {
            "profileId": 9999999999999999,
            "countryCode": "CA",
            "accountInfo": {"name": "Solid Gold Pet", "type": "seller"},
        },
    ])

    result = await profile_tools.set_active_profile("3194577320222553")

    assert result["success"] is True
    assert result["profile_id"] == "3194577320222553"
    assert result["name"] == "Solid Gold Pet"
    assert result["country_code"] == "US"
    assert result["account_type"] == "seller"
    # Message must include the contextual suffix so a non-structured client
    # surfacing only `message` still sees the marketplace.
    assert "Solid Gold Pet" in result["message"]
    assert "US" in result["message"]
    assert "seller" in result["message"]


@pytest.mark.asyncio
async def test_set_active_profile_handles_missing_account_info(monkeypatch):
    """F6 backward-compat: cached profile without accountInfo still produces
    a valid response (None for missing fields, plain message)."""
    manager = SimpleNamespace(set_active_profile_id=MagicMock())
    monkeypatch.setattr(profile_tools, "get_auth_manager", lambda: manager)
    # No accountInfo, no countryCode — minimal cached entry.
    _mock_cached_profiles_full(monkeypatch, [{"profileId": 123}])

    result = await profile_tools.set_active_profile("123")

    assert result["success"] is True
    assert result["profile_id"] == "123"
    assert result["name"] is None
    assert result["country_code"] is None
    assert result["account_type"] is None
    # Message degrades to the plain form when no metadata is available.
    assert result["message"] == "Active profile set to 123"


@pytest.mark.asyncio
async def test_set_active_profile_response_validates_against_model(monkeypatch):
    """F6: returned dict must validate against SetProfileResponse so the new
    optional fields are part of the documented contract."""
    from amazon_ads_mcp.models.builtin_responses import SetProfileResponse

    manager = SimpleNamespace(set_active_profile_id=MagicMock())
    monkeypatch.setattr(profile_tools, "get_auth_manager", lambda: manager)
    _mock_cached_profiles_full(monkeypatch, [
        {
            "profileId": 123,
            "countryCode": "MX",
            "accountInfo": {"name": "Brand", "type": "vendor"},
        }
    ])

    result = await profile_tools.set_active_profile("123")
    # Round-trip through the Pydantic model — fails if any required field
    # is missing or any new field is the wrong type.
    parsed = SetProfileResponse.model_validate(result)
    assert parsed.name == "Brand"
    assert parsed.country_code == "MX"
    assert parsed.account_type == "vendor"


@pytest.mark.asyncio
async def test_get_active_profile_with_profile(monkeypatch):
    manager = SimpleNamespace(
        get_active_profile_id=MagicMock(return_value="123"),
        get_profile_source=MagicMock(return_value="explicit"),
    )
    monkeypatch.setattr(profile_tools, "get_auth_manager", lambda: manager)

    result = await profile_tools.get_active_profile()

    assert result["success"] is True
    assert result["profile_id"] == "123"
    assert result["source"] == "explicit"


@pytest.mark.asyncio
async def test_get_active_profile_missing(monkeypatch):
    manager = SimpleNamespace(get_active_profile_id=MagicMock(return_value=None))
    monkeypatch.setattr(profile_tools, "get_auth_manager", lambda: manager)

    result = await profile_tools.get_active_profile()

    assert result["success"] is True
    assert result["profile_id"] is None


@pytest.mark.asyncio
async def test_clear_active_profile_with_fallback(monkeypatch):
    manager = SimpleNamespace(
        clear_active_profile_id=MagicMock(),
        get_active_profile_id=MagicMock(return_value="fallback"),
    )
    monkeypatch.setattr(profile_tools, "get_auth_manager", lambda: manager)

    result = await profile_tools.clear_active_profile()

    assert result["success"] is True
    assert result["fallback_profile_id"] == "fallback"


@pytest.mark.asyncio
async def test_clear_active_profile_no_fallback(monkeypatch):
    manager = SimpleNamespace(
        clear_active_profile_id=MagicMock(),
        get_active_profile_id=MagicMock(return_value=None),
    )
    monkeypatch.setattr(profile_tools, "get_auth_manager", lambda: manager)

    result = await profile_tools.clear_active_profile()

    assert result["success"] is True
    assert "no fallback" in result["message"]
