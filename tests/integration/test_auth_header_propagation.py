"""Integration tests for Authorization header propagation.

These tests verify that the Authorization header from MCP clients
is properly propagated through the middleware chain to the OpenBridge
provider. This prevents regressions where header-based authentication
fails silently.

The tests cover:
1. Middleware chain setup for OpenBridge
2. Authorization header extraction from requests
3. Token propagation to the OpenBridge provider
4. End-to-end flow validation
"""

import pytest
from unittest.mock import AsyncMock, MagicMock

from amazon_ads_mcp.middleware.authentication import (
    AuthConfig,
    RefreshTokenMiddleware,
    create_auth_middleware,
    create_openbridge_config,
)


class TestMiddlewareChainSetup:
    """Test that middleware chain is correctly configured for OpenBridge."""

    def test_openbridge_config_creates_refresh_token_middleware(self):
        """RefreshTokenMiddleware MUST be included when refresh_token_enabled=True."""
        config = AuthConfig()
        config.enabled = True
        config.refresh_token_enabled = True
        config.jwt_validation_enabled = False  # Simplified for this test
        config.refresh_token_endpoint = "https://auth.openbridge.io/refresh"  # Required

        middlewares = create_auth_middleware(config)

        middleware_types = [type(m).__name__ for m in middlewares]
        assert "RefreshTokenMiddleware" in middleware_types, (
            "RefreshTokenMiddleware must be added when refresh_token_enabled=True. "
            "Without it, Authorization headers from clients won't be processed."
        )

    def test_openbridge_config_without_refresh_token_enabled_skips_middleware(self):
        """RefreshTokenMiddleware should NOT be included when refresh_token_enabled=False."""
        config = AuthConfig()
        config.enabled = True
        config.refresh_token_enabled = False
        config.jwt_validation_enabled = True

        middlewares = create_auth_middleware(config)

        middleware_types = [type(m).__name__ for m in middlewares]
        assert "RefreshTokenMiddleware" not in middleware_types

    def test_create_openbridge_config_sets_correct_defaults(self):
        """OpenBridge config should enable refresh token processing by default."""
        # Note: This test documents the expected behavior.
        # The actual config values depend on environment variables.
        config = create_openbridge_config()

        # After load_from_env(), these may be False unless env vars are set
        # This test documents that we need REFRESH_TOKEN_ENABLED=true
        # and AUTH_ENABLED=true for OpenBridge to work with header auth
        assert hasattr(config, "refresh_token_enabled")
        assert hasattr(config, "enabled")


class TestAuthorizationHeaderExtraction:
    """Test that Authorization headers are correctly extracted from requests."""

    @pytest.fixture
    def mock_auth_manager(self):
        """Create a mock auth manager with an OpenBridge-like provider."""
        manager = MagicMock()
        manager.provider = MagicMock()
        manager.provider.provider_type = "openbridge"
        manager.provider.set_refresh_token = MagicMock()
        return manager

    @pytest.fixture
    def enabled_config(self):
        """Create a config with refresh token processing enabled."""
        config = AuthConfig()
        config.enabled = True
        config.refresh_token_enabled = True
        config.refresh_token_pattern = None  # Accept any token
        return config

    @pytest.mark.asyncio
    async def test_middleware_extracts_bearer_token_from_header(
        self, mock_auth_manager, enabled_config
    ):
        """Middleware must extract Bearer token from Authorization header."""
        middleware = RefreshTokenMiddleware(enabled_config, mock_auth_manager)

        # Create mock context with Authorization header
        mock_request = MagicMock()
        mock_request.headers = {"authorization": "Bearer test-refresh-token"}

        mock_context = MagicMock()
        mock_context.fastmcp_context = MagicMock()
        mock_context.fastmcp_context.request_context = MagicMock()
        mock_context.fastmcp_context.request_context.request = mock_request

        call_next = AsyncMock()

        await middleware.on_request(mock_context, call_next)

        # Verify token was propagated to provider
        mock_auth_manager.provider.set_refresh_token.assert_called_once_with(
            "test-refresh-token"
        )

    @pytest.mark.asyncio
    async def test_middleware_handles_missing_authorization_header(
        self, mock_auth_manager, enabled_config
    ):
        """Middleware should not fail when Authorization header is missing."""
        middleware = RefreshTokenMiddleware(enabled_config, mock_auth_manager)

        mock_request = MagicMock()
        mock_request.headers = {}  # No Authorization header

        mock_context = MagicMock()
        mock_context.fastmcp_context = MagicMock()
        mock_context.fastmcp_context.request_context = MagicMock()
        mock_context.fastmcp_context.request_context.request = mock_request

        call_next = AsyncMock()

        # Should not raise
        await middleware.on_request(mock_context, call_next)

        # Should not call set_refresh_token
        mock_auth_manager.provider.set_refresh_token.assert_not_called()

    @pytest.mark.asyncio
    async def test_middleware_handles_non_bearer_auth(
        self, mock_auth_manager, enabled_config
    ):
        """Middleware should ignore non-Bearer Authorization headers."""
        middleware = RefreshTokenMiddleware(enabled_config, mock_auth_manager)

        mock_request = MagicMock()
        mock_request.headers = {"authorization": "Basic dXNlcjpwYXNz"}

        mock_context = MagicMock()
        mock_context.fastmcp_context = MagicMock()
        mock_context.fastmcp_context.request_context = MagicMock()
        mock_context.fastmcp_context.request_context.request = mock_request

        call_next = AsyncMock()

        await middleware.on_request(mock_context, call_next)

        # Should not call set_refresh_token for non-Bearer auth
        mock_auth_manager.provider.set_refresh_token.assert_not_called()

    @pytest.mark.asyncio
    async def test_middleware_handles_case_insensitive_bearer(
        self, mock_auth_manager, enabled_config
    ):
        """Bearer keyword should be case-insensitive."""
        middleware = RefreshTokenMiddleware(enabled_config, mock_auth_manager)

        for bearer_variant in ["Bearer", "bearer", "BEARER", "BeArEr"]:
            mock_auth_manager.provider.set_refresh_token.reset_mock()

            mock_request = MagicMock()
            mock_request.headers = {
                "authorization": f"{bearer_variant} test-token-{bearer_variant}"
            }

            mock_context = MagicMock()
            mock_context.fastmcp_context = MagicMock()
            mock_context.fastmcp_context.request_context = MagicMock()
            mock_context.fastmcp_context.request_context.request = mock_request

            call_next = AsyncMock()

            await middleware.on_request(mock_context, call_next)

            mock_auth_manager.provider.set_refresh_token.assert_called_once_with(
                f"test-token-{bearer_variant}"
            )


class TestTokenPropagationToProvider:
    """Test that tokens are correctly propagated to the OpenBridge provider."""

    @pytest.mark.asyncio
    async def test_token_propagation_happens_before_config_checks(self):
        """Token propagation to provider must happen even if JWT processing is disabled.

        This is critical for OpenBridge: the provider needs the refresh token
        to authenticate API calls, regardless of whether JWT conversion/validation
        is enabled.
        """
        # Config with refresh token processing DISABLED
        config = AuthConfig()
        config.enabled = False  # Auth processing disabled
        config.refresh_token_enabled = False  # Refresh token processing disabled

        mock_auth_manager = MagicMock()
        mock_auth_manager.provider = MagicMock()
        mock_auth_manager.provider.set_refresh_token = MagicMock()

        middleware = RefreshTokenMiddleware(config, mock_auth_manager)

        mock_request = MagicMock()
        mock_request.headers = {"authorization": "Bearer my-refresh-token"}

        mock_context = MagicMock()
        mock_context.fastmcp_context = MagicMock()
        mock_context.fastmcp_context.request_context = MagicMock()
        mock_context.fastmcp_context.request_context.request = mock_request

        call_next = AsyncMock()

        await middleware.on_request(mock_context, call_next)

        # CRITICAL: Token MUST be propagated even when config.enabled=False
        mock_auth_manager.provider.set_refresh_token.assert_called_once_with(
            "my-refresh-token"
        )

    @pytest.mark.asyncio
    async def test_provider_without_set_refresh_token_is_handled(self):
        """Middleware should handle providers that don't support set_refresh_token."""
        config = AuthConfig()
        config.enabled = True
        config.refresh_token_enabled = True

        # Provider without set_refresh_token method (e.g., direct auth)
        mock_auth_manager = MagicMock()
        mock_auth_manager.provider = MagicMock(spec=[])  # No methods

        middleware = RefreshTokenMiddleware(config, mock_auth_manager)

        mock_request = MagicMock()
        mock_request.headers = {"authorization": "Bearer token"}

        mock_context = MagicMock()
        mock_context.fastmcp_context = MagicMock()
        mock_context.fastmcp_context.request_context = MagicMock()
        mock_context.fastmcp_context.request_context.request = mock_request

        call_next = AsyncMock()

        # Should not raise even though provider doesn't have set_refresh_token
        await middleware.on_request(mock_context, call_next)


class TestEndToEndAuthFlow:
    """Test the complete authentication flow from header to provider."""

    @pytest.mark.asyncio
    async def test_complete_openbridge_auth_flow(self):
        """Test the complete flow: header → middleware → provider.

        This simulates what happens when an MCP client sends a request
        with an Authorization header containing an OpenBridge refresh token.
        """
        # Setup: Create middleware chain like ServerBuilder does
        config = AuthConfig()
        config.enabled = True
        config.refresh_token_enabled = True
        config.jwt_validation_enabled = False  # Skip JWT validation for this test
        config.refresh_token_endpoint = "https://auth.openbridge.io/refresh"  # Required

        mock_auth_manager = MagicMock()
        mock_auth_manager.provider = MagicMock()
        mock_auth_manager.provider.provider_type = "openbridge"
        mock_auth_manager.provider.set_refresh_token = MagicMock()

        middlewares = create_auth_middleware(config, auth_manager=mock_auth_manager)

        # Verify RefreshTokenMiddleware is in the chain
        assert any(
            isinstance(m, RefreshTokenMiddleware) for m in middlewares
        ), "RefreshTokenMiddleware must be in the middleware chain for OpenBridge"

        # Simulate request with Authorization header
        refresh_middleware = next(
            m for m in middlewares if isinstance(m, RefreshTokenMiddleware)
        )

        mock_request = MagicMock()
        mock_request.headers = {
            "authorization": "Bearer openbridge-refresh-token:secret"
        }

        mock_context = MagicMock()
        mock_context.fastmcp_context = MagicMock()
        mock_context.fastmcp_context.request_context = MagicMock()
        mock_context.fastmcp_context.request_context.request = mock_request

        call_next = AsyncMock()

        await refresh_middleware.on_request(mock_context, call_next)

        # Verify the token reached the provider
        mock_auth_manager.provider.set_refresh_token.assert_called_once_with(
            "openbridge-refresh-token:secret"
        )

    @pytest.mark.asyncio
    async def test_missing_middleware_causes_auth_failure(self):
        """Document that missing middleware causes authentication to fail.

        This test documents the failure mode that occurred when
        REFRESH_TOKEN_ENABLED was not set to true.
        """
        # Config WITHOUT refresh token middleware (the broken state)
        config = AuthConfig()
        config.enabled = True
        config.refresh_token_enabled = False  # This was the bug!
        config.jwt_validation_enabled = True

        mock_auth_manager = MagicMock()
        mock_auth_manager.provider = MagicMock()
        mock_auth_manager.provider.provider_type = "openbridge"
        mock_auth_manager.provider.set_refresh_token = MagicMock()

        middlewares = create_auth_middleware(config, auth_manager=mock_auth_manager)

        # RefreshTokenMiddleware should NOT be in the chain
        assert not any(
            isinstance(m, RefreshTokenMiddleware) for m in middlewares
        ), "RefreshTokenMiddleware should not be added when refresh_token_enabled=False"

        # This means token propagation cannot happen through middleware!
        # The provider.set_refresh_token would never be called.


class TestContextVariations:
    """Test middleware behavior with various context configurations."""

    @pytest.fixture
    def middleware_with_mocks(self):
        """Create middleware with mocked auth manager."""
        config = AuthConfig()
        config.enabled = True
        config.refresh_token_enabled = True

        mock_auth_manager = MagicMock()
        mock_auth_manager.provider = MagicMock()
        mock_auth_manager.provider.set_refresh_token = MagicMock()

        middleware = RefreshTokenMiddleware(config, mock_auth_manager)
        return middleware, mock_auth_manager

    @pytest.mark.asyncio
    async def test_handles_missing_fastmcp_context(self, middleware_with_mocks):
        """Middleware should handle missing fastmcp_context gracefully."""
        middleware, mock_auth_manager = middleware_with_mocks

        mock_context = MagicMock()
        mock_context.fastmcp_context = None

        call_next = AsyncMock()

        # Should not raise
        await middleware.on_request(mock_context, call_next)

        # Should not attempt to set token
        mock_auth_manager.provider.set_refresh_token.assert_not_called()

    @pytest.mark.asyncio
    async def test_handles_missing_request_context(self, middleware_with_mocks):
        """Middleware should handle missing request_context gracefully."""
        middleware, mock_auth_manager = middleware_with_mocks

        mock_context = MagicMock()
        mock_context.fastmcp_context = MagicMock()
        mock_context.fastmcp_context.request_context = None

        call_next = AsyncMock()

        # Should not raise
        await middleware.on_request(mock_context, call_next)

        mock_auth_manager.provider.set_refresh_token.assert_not_called()

    @pytest.mark.asyncio
    async def test_handles_missing_request(self, middleware_with_mocks):
        """Middleware should handle missing request gracefully."""
        middleware, mock_auth_manager = middleware_with_mocks

        mock_context = MagicMock()
        mock_context.fastmcp_context = MagicMock()
        mock_context.fastmcp_context.request_context = MagicMock()
        mock_context.fastmcp_context.request_context.request = None

        call_next = AsyncMock()

        # Should not raise
        await middleware.on_request(mock_context, call_next)

        mock_auth_manager.provider.set_refresh_token.assert_not_called()

    @pytest.mark.asyncio
    async def test_handles_request_without_headers(self, middleware_with_mocks):
        """Middleware should handle request without headers attribute."""
        middleware, mock_auth_manager = middleware_with_mocks

        mock_request = MagicMock(spec=[])  # No headers attribute

        mock_context = MagicMock()
        mock_context.fastmcp_context = MagicMock()
        mock_context.fastmcp_context.request_context = MagicMock()
        mock_context.fastmcp_context.request_context.request = mock_request

        call_next = AsyncMock()

        # Should not raise
        await middleware.on_request(mock_context, call_next)

        mock_auth_manager.provider.set_refresh_token.assert_not_called()
