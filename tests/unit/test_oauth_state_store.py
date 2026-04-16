"""Tests for OAuth state signing and validation."""

from amazon_ads_mcp.auth.oauth_state_store import OAuthStateStore


def test_state_signature_is_full_sha256():
    """The HMAC signature component of the state must be the full SHA-256
    hex digest (64 chars), not a truncated prefix. Truncation weakens
    forgery resistance."""
    store = OAuthStateStore(secret_key="test-secret")
    state = store.generate_state(auth_url="https://example.com/auth")

    state_base, signature = state.rsplit(".", 1)
    assert len(signature) == 64
    assert all(c in "0123456789abcdef" for c in signature)
    # state_base should still be a reasonable length
    assert len(state_base) >= 16


def test_state_validates_roundtrip():
    store = OAuthStateStore(secret_key="test-secret")
    state = store.generate_state(auth_url="https://example.com/auth")

    ok, err = store.validate_state(state)
    assert ok is True
    assert err is None


def test_state_rejects_forged_signature():
    store = OAuthStateStore(secret_key="test-secret")
    state = store.generate_state(auth_url="https://example.com/auth")
    state_base, _ = state.rsplit(".", 1)
    forged = f"{state_base}.{'0' * 64}"

    # The forged state is not in the in-memory map either, so it should be
    # rejected on either the existence check or the signature check.
    ok, err = store.validate_state(forged)
    assert ok is False
    assert err is not None


def test_state_rejects_tampered_existing_entry():
    """Even if the attacker knows a valid state token's prefix, swapping
    the signature suffix to garbage must fail signature validation."""
    store = OAuthStateStore(secret_key="test-secret")
    state = store.generate_state(auth_url="https://example.com/auth")

    # Inject a second state with the same base but a wrong signature by
    # directly manipulating the store to simulate an attacker-chosen token
    # that made it into storage (e.g. via a replay attempt).
    state_base, _ = state.rsplit(".", 1)
    tampered = f"{state_base}.{'f' * 64}"
    store._memory_store[tampered] = store._memory_store[state]

    ok, err = store.validate_state(tampered)
    assert ok is False
    assert err == "Invalid state signature"
