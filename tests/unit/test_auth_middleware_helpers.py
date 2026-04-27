"""Coverage-pushing tests for ``middleware.authentication`` helpers.

Targets the easy-to-test surface:
- ``AuthConfig`` env loading, validation, handler registration
- ``JWTCache`` get/set/expiry/cleanup
- Factory functions: ``create_json_api_refresh_token_config``,
  ``create_openbridge_config``, ``create_auth0_config``

The complex middleware classes (``RefreshTokenMiddleware``,
``JWTAuthenticationMiddleware``) are covered by existing
``test_authentication_middleware.py`` and ``test_auth_header_propagation.py``;
this file fills in the rest.
"""

from __future__ import annotations

import time

import pytest

from amazon_ads_mcp.middleware.authentication import (
    AuthConfig,
    JWTCache,
    create_auth0_config,
    create_json_api_refresh_token_config,
    create_openbridge_config,
)


# --- AuthConfig ---------------------------------------------------------


class TestAuthConfigDefaults:
    def test_init_disables_everything(self) -> None:
        c = AuthConfig()
        assert c.enabled is False
        assert c.jwt_validation_enabled is False
        assert c.refresh_token_enabled is False

    def test_default_jwt_settings_strict(self) -> None:
        c = AuthConfig()
        assert c.jwt_verify_signature is True
        assert c.jwt_verify_iss is True
        assert c.jwt_verify_aud is True
        assert c.jwt_required_claims == []

    def test_default_cache_ttl(self) -> None:
        c = AuthConfig()
        assert c.jwt_cache_ttl == 3000  # 50 min — matches OpenBridge JWT lifetime
        assert c.cache_cleanup_interval == 300


class TestAuthConfigLoadFromEnv:
    def test_auth_disabled_by_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # No AUTH_ENABLED env var → False
        monkeypatch.delenv("AUTH_ENABLED", raising=False)
        c = AuthConfig()
        c.load_from_env()
        assert c.enabled is False

    def test_auth_enabled_via_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AUTH_ENABLED", "true")
        c = AuthConfig()
        c.load_from_env()
        assert c.enabled is True

    def test_auth_enabled_case_insensitive(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AUTH_ENABLED", "TRUE")
        c = AuthConfig()
        c.load_from_env()
        assert c.enabled is True

    def test_jwt_settings_loaded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("JWT_ISSUER", "https://issuer.example.com/")
        monkeypatch.setenv("JWT_AUDIENCE", "my-api")
        monkeypatch.setenv("JWT_JWKS_URI", "https://issuer.example.com/.well-known/jwks.json")
        c = AuthConfig()
        c.load_from_env()
        assert c.jwt_issuer == "https://issuer.example.com/"
        assert c.jwt_audience == "my-api"
        assert "jwks.json" in c.jwt_jwks_uri

    def test_required_claims_split_on_comma(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("JWT_REQUIRED_CLAIMS", "user_id, account_id ,scope")
        c = AuthConfig()
        c.load_from_env()
        # Whitespace stripped per claim
        assert c.jwt_required_claims == ["user_id", "account_id", "scope"]

    def test_invalid_cache_ttl_logs_and_keeps_default(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        monkeypatch.setenv("JWT_CACHE_TTL", "not-a-number")
        c = AuthConfig()
        c.load_from_env()
        # Should fall back to default
        assert c.jwt_cache_ttl == 3000

    def test_valid_cache_ttl_overrides_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("JWT_CACHE_TTL", "1800")
        c = AuthConfig()
        c.load_from_env()
        assert c.jwt_cache_ttl == 1800

    def test_load_from_env_does_not_overwrite_existing_endpoint(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("REFRESH_TOKEN_ENDPOINT", "https://env.example/refresh")
        c = AuthConfig()
        c.refresh_token_endpoint = "https://preset.example/refresh"
        c.load_from_env()
        # Pre-set value preserved
        assert c.refresh_token_endpoint == "https://preset.example/refresh"


class TestAuthConfigSetHandlers:
    def test_handlers_stored(self) -> None:
        c = AuthConfig()

        def builder(t: str) -> dict:
            return {"t": t}

        def parser(d: dict):
            return d.get("t")

        def detector(t: str) -> bool:
            return True

        c.set_refresh_token_handlers(builder, parser, detector)
        assert c.refresh_token_request_builder is builder
        assert c.refresh_token_response_parser is parser
        assert c.refresh_token_pattern is detector

    def test_pattern_detector_is_optional(self) -> None:
        c = AuthConfig()
        c.set_refresh_token_handlers(lambda t: {}, lambda d: None)
        assert c.refresh_token_pattern is None


class TestAuthConfigValidate:
    def test_disabled_config_always_valid(self) -> None:
        c = AuthConfig()
        c.enabled = False
        assert c.validate() is True


# --- JWTCache -----------------------------------------------------------


class TestJWTCache:
    def test_get_missing_returns_none(self) -> None:
        cache = JWTCache(ttl=10)
        assert cache.get("nonexistent") is None

    def test_set_and_get_round_trip(self) -> None:
        cache = JWTCache(ttl=10)
        cache.set("user-1", "jwt-token-123")
        assert cache.get("user-1") == "jwt-token-123"

    def test_expired_entry_returns_none(self) -> None:
        cache = JWTCache(ttl=0)  # immediate expiry
        cache.set("user-1", "jwt")
        time.sleep(0.01)  # ensure clock advances past 0-ttl expiry
        assert cache.get("user-1") is None

    def test_overwrite_existing_key(self) -> None:
        cache = JWTCache(ttl=100)
        cache.set("k", "first")
        cache.set("k", "second")
        assert cache.get("k") == "second"

    def test_separate_keys_independent(self) -> None:
        cache = JWTCache(ttl=100)
        cache.set("a", "ja")
        cache.set("b", "jb")
        assert cache.get("a") == "ja"
        assert cache.get("b") == "jb"


# --- create_json_api_refresh_token_config -------------------------------


class TestJsonApiRefreshTokenConfig:
    def test_endpoint_set(self) -> None:
        c = create_json_api_refresh_token_config(
            endpoint_url="https://api.example/refresh",
            token_type_name="APIAuth",
            required_claims=["user_id"],
        )
        assert c.refresh_token_endpoint == "https://api.example/refresh"

    def test_required_claims_set(self) -> None:
        c = create_json_api_refresh_token_config(
            endpoint_url="https://x", token_type_name="T",
            required_claims=["a", "b", "c"],
        )
        assert c.jwt_required_claims == ["a", "b", "c"]

    def test_signature_verification_default_true(self) -> None:
        c = create_json_api_refresh_token_config(
            endpoint_url="https://x", token_type_name="T",
            required_claims=[],
        )
        assert c.jwt_verify_signature is True

    def test_signature_verification_can_be_disabled(self) -> None:
        c = create_json_api_refresh_token_config(
            endpoint_url="https://x", token_type_name="T",
            required_claims=[], verify_signature=False,
        )
        assert c.jwt_verify_signature is False

    def test_request_builder_wraps_in_jsonapi_envelope(self) -> None:
        c = create_json_api_refresh_token_config(
            endpoint_url="https://x", token_type_name="MyResource",
            required_claims=[],
        )
        out = c.refresh_token_request_builder("refresh-abc")
        assert out == {
            "data": {
                "type": "MyResource",
                "attributes": {"refresh_token": "refresh-abc"},
            }
        }

    def test_response_parser_extracts_token(self) -> None:
        c = create_json_api_refresh_token_config(
            endpoint_url="https://x", token_type_name="T",
            required_claims=[],
        )
        out = c.refresh_token_response_parser({
            "data": {"attributes": {"token": "jwt-xyz"}}
        })
        assert out == "jwt-xyz"

    def test_response_parser_missing_data_returns_none(self) -> None:
        c = create_json_api_refresh_token_config(
            endpoint_url="https://x", token_type_name="T",
            required_claims=[],
        )
        assert c.refresh_token_response_parser({}) is None

    def test_response_parser_handles_malformed(self) -> None:
        c = create_json_api_refresh_token_config(
            endpoint_url="https://x", token_type_name="T",
            required_claims=[],
        )
        # Even shape-violating input should not raise
        assert c.refresh_token_response_parser({"data": "not-a-dict"}) is None

    def test_pattern_detector_matches_colon_long_tokens(self) -> None:
        c = create_json_api_refresh_token_config(
            endpoint_url="https://x", token_type_name="T",
            required_claims=[],
        )
        # OpenBridge-style refresh tokens
        assert c.refresh_token_pattern("ob:" + "x" * 50) is True

    def test_pattern_detector_rejects_short_no_colon(self) -> None:
        c = create_json_api_refresh_token_config(
            endpoint_url="https://x", token_type_name="T",
            required_claims=[],
        )
        # Short / no colon → not a refresh token
        assert c.refresh_token_pattern("plain-jwt") is False
        assert c.refresh_token_pattern("ab:cd") is False  # too short


# --- create_openbridge_config -------------------------------------------


class TestOpenbridgeConfig:
    def test_uses_default_auth_base_url(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("OPENBRIDGE_AUTH_BASE_URL", raising=False)
        monkeypatch.delenv("REFRESH_TOKEN_ENDPOINT", raising=False)
        c = create_openbridge_config()
        assert c.refresh_token_endpoint == (
            "https://authentication.api.openbridge.io/auth/api/refresh"
        )

    def test_explicit_refresh_endpoint_overrides_base(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("REFRESH_TOKEN_ENDPOINT", "https://custom/refresh")
        c = create_openbridge_config()
        assert c.refresh_token_endpoint == "https://custom/refresh"

    def test_always_enabled_for_openbridge(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Critical regression: even without env vars, OpenBridge must
        ship enabled to avoid silently broken auth on Cloud Run."""
        monkeypatch.delenv("AUTH_ENABLED", raising=False)
        monkeypatch.delenv("REFRESH_TOKEN_ENABLED", raising=False)
        c = create_openbridge_config()
        assert c.enabled is True
        assert c.refresh_token_enabled is True

    def test_iss_aud_signature_settings_documented_quirk(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Latent bug pinned (see ``docs/audit/latent-issues.md`` #3):
        create_openbridge_config sets
        jwt_verify_signature=False, jwt_verify_iss=False, jwt_verify_aud=False
        — then calls load_from_env() which RE-READS those env vars and
        OVERWRITES them with True (the documented env-var defaults).

        The intent in the helper docstring is "iss/aud/signature verification
        disabled for OpenBridge", but in practice the env-load overwrites
        win unless the operator explicitly sets ``JWT_VERIFY_SIGNATURE=false``.

        This is masked in production by ``jwt_validation_enabled`` defaulting
        to False (so the verify_* flags are dead code in default deployments),
        but a user setting ``JWT_VALIDATION_ENABLED=true`` without also setting
        the verify_* env vars would hit broken auth.

        Test the ACTUAL behavior so any future fix breaks the test loudly
        and the maintainer can ratify the change.
        """
        # Clear all relevant env vars so we see the env-defaults path
        for var in ("JWT_VERIFY_SIGNATURE", "JWT_VERIFY_ISS", "JWT_VERIFY_AUD"):
            monkeypatch.delenv(var, raising=False)
        c = create_openbridge_config()
        # Current (unintended) behavior: env defaults restore True.
        assert c.jwt_verify_signature is True
        assert c.jwt_verify_iss is True
        assert c.jwt_verify_aud is True

    def test_signature_verification_can_be_disabled_via_env(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The escape hatch: explicit env var beats the load_from_env
        default-to-True clobber."""
        monkeypatch.setenv("JWT_VERIFY_SIGNATURE", "false")
        c = create_openbridge_config()
        assert c.jwt_verify_signature is False

    def test_jwt_validation_off_by_default(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("JWT_VALIDATION_ENABLED", raising=False)
        c = create_openbridge_config()
        # JWT validation defaults OFF for OpenBridge per round-N comment in src
        assert c.jwt_validation_enabled is False

    def test_jwt_validation_can_be_enabled_via_env(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("JWT_VALIDATION_ENABLED", "true")
        c = create_openbridge_config()
        assert c.jwt_validation_enabled is True


# --- create_auth0_config ------------------------------------------------


class TestAuth0Config:
    def test_issuer_url_built_from_domain(self) -> None:
        c = create_auth0_config(domain="example.auth0.com", audience="https://api")
        assert c.jwt_issuer == "https://example.auth0.com/"

    def test_jwks_uri_built_from_domain(self) -> None:
        c = create_auth0_config(domain="example.auth0.com", audience="https://api")
        assert c.jwt_jwks_uri == "https://example.auth0.com/.well-known/jwks.json"

    def test_audience_set(self) -> None:
        c = create_auth0_config(domain="x", audience="my-api")
        assert c.jwt_audience == "my-api"
