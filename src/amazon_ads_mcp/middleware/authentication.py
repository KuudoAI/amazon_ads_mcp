"""Reusable FastMCP Authentication Middleware - Version 5.0 (Production Ready).

This module provides a comprehensive authentication middleware system for
FastMCP servers with support for JWT validation, refresh token conversion,
and context-safe token sharing between middleware components.

The module provides:
- AuthConfig: Configuration management for authentication settings
- JWTCache: Thread-safe JWT caching with automatic cleanup
- RefreshTokenMiddleware: Converts refresh tokens to JWT tokens
- JWTAuthenticationMiddleware: Validates JWT tokens with comprehensive error handling
- Utility functions for accessing JWT data and creating middleware chains
- Pre-configured configurations for common providers (OpenBridge, Auth0, JSON:API)

Key Features:
- FastMCP-compliant middleware patterns with proper hooks
- Context-safe JWT storage using contextvars for async safety
- JWT caching to reduce API calls and improve performance
- Comprehensive error handling and detailed logging
- OpenBridge-specific validation (user_id, account_id claims)
- Environment variable configuration for operator control
- Client disconnection handling and timeout management
- Support for multiple authentication providers

Examples:
    >>> from .middleware.authentication import create_auth_middleware
    >>> middleware = create_auth_middleware()  # Auto-configure from environment

    >>> # Use with specific configuration
    >>> config = AuthConfig()
    >>> config.load_from_env()
    >>> middleware = create_auth_middleware(config)

    >>> # Access JWT data in other parts of the application
    >>> from .middleware.authentication import get_current_claims
    >>> claims = get_current_claims()
    >>> print(f"User ID: {claims.get('user_id')}")
"""

import logging
import os
import threading
import time
from contextvars import ContextVar
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Optional, Tuple

import httpx
import jwt
from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import Middleware, MiddlewareContext

from ..utils.http import get_http_client
from ..utils.security import sanitize_string

# Context-safe storage for sharing JWT tokens between middleware
# Using contextvars instead of threading.local() for async safety
jwt_token_var: ContextVar[Optional[str]] = ContextVar("jwt_token", default=None)
jwt_claims_var: ContextVar[Optional[dict]] = ContextVar("jwt_claims", default=None)

logger = logging.getLogger(__name__)


class AuthConfig:
    """Configuration for authentication middleware.

    This class manages all configuration settings for the authentication
    middleware system, including JWT validation, refresh token conversion,
    and caching settings. It supports loading configuration from environment
    variables and provides validation methods.

    The class handles:
    - JWT validation settings (issuer, audience, signature verification)
    - Refresh token conversion settings and handlers
    - Caching configuration and TTL settings
    - Environment variable loading and validation
    - Provider-specific configurations

    Key Features:
    - Environment variable configuration for operator control
    - Validation of configuration completeness
    - Support for multiple authentication providers
    - Flexible refresh token handler configuration
    - Comprehensive JWT validation options

    Examples:
        >>> config = AuthConfig()
        >>> config.load_from_env()
        >>> if config.validate():
        ...     print("Configuration is valid")

        >>> # Configure refresh token handlers
        >>> config.set_refresh_token_handlers(
        ...     request_builder=lambda token: {"token": token},
        ...     response_parser=lambda data: data.get("jwt")
        ... )
    """

    def __init__(self):
        # General settings
        self.enabled = False
        self.jwt_validation_enabled = False
        self.refresh_token_enabled = False

        # JWT validation settings
        self.jwt_issuer: Optional[str] = None
        self.jwt_audience: Optional[str] = None
        self.jwt_jwks_uri: Optional[str] = None
        self.jwt_public_key: Optional[str] = None
        self.jwt_verify_signature = True
        self.jwt_verify_iss = True
        self.jwt_verify_aud = True
        self.jwt_required_claims: list[str] = []

        # Refresh token settings
        self.refresh_token_endpoint: Optional[str] = None
        self.refresh_token_request_builder: Optional[Callable[[str], dict]] = None
        self.refresh_token_response_parser: Optional[
            Callable[[dict], Optional[str]]
        ] = None
        self.refresh_token_pattern: Optional[Callable[[str], bool]] = None

        # Caching settings
        self.jwt_cache_ttl = 3000  # 50 minutes (OpenBridge JWTs typically last 1 hour)
        self.cache_cleanup_interval = 300  # 5 minutes

    def load_from_env(self) -> None:
        """Load configuration from environment variables.

        This method loads all authentication configuration settings from
        environment variables, providing operator control over the
        authentication system without code changes.

        Environment Variables:
        - AUTH_ENABLED: Enable/disable authentication (default: false)
        - JWT_VALIDATION_ENABLED: Enable JWT validation (default: true)
        - REFRESH_TOKEN_ENABLED: Enable refresh token conversion (default: false)
        - JWT_ISSUER: JWT issuer for validation
        - JWT_AUDIENCE: JWT audience for validation
        - JWT_JWKS_URI: JWKS endpoint for public key retrieval
        - JWT_PUBLIC_KEY: Static public key for JWT validation
        - JWT_VERIFY_SIGNATURE: Enable signature verification (default: true)
        - JWT_VERIFY_ISS: Enable issuer verification (default: true)
        - JWT_VERIFY_AUD: Enable audience verification (default: true)
        - JWT_REQUIRED_CLAIMS: Comma-separated list of required claims
        - REFRESH_TOKEN_ENDPOINT: Endpoint for refresh token conversion
        - JWT_CACHE_TTL: JWT cache TTL in seconds (default: 3000)

        Examples:
            >>> config = AuthConfig()
            >>> config.load_from_env()
            >>> print(f"Authentication enabled: {config.enabled}")
        """
        self.enabled = os.getenv("AUTH_ENABLED", "false").lower() == "true"
        self.jwt_validation_enabled = (
            os.getenv("JWT_VALIDATION_ENABLED", "true").lower() == "true"
        )
        self.refresh_token_enabled = (
            os.getenv("REFRESH_TOKEN_ENABLED", "false").lower() == "true"
        )

        # JWT settings
        self.jwt_issuer = os.getenv("JWT_ISSUER")
        self.jwt_audience = os.getenv("JWT_AUDIENCE")
        self.jwt_jwks_uri = os.getenv("JWT_JWKS_URI")
        self.jwt_public_key = os.getenv("JWT_PUBLIC_KEY")
        self.jwt_verify_signature = (
            os.getenv("JWT_VERIFY_SIGNATURE", "true").lower() == "true"
        )
        self.jwt_verify_iss = os.getenv("JWT_VERIFY_ISS", "true").lower() == "true"
        self.jwt_verify_aud = os.getenv("JWT_VERIFY_AUD", "true").lower() == "true"

        if os.getenv("JWT_REQUIRED_CLAIMS"):
            self.jwt_required_claims = [
                c.strip() for c in os.getenv("JWT_REQUIRED_CLAIMS").split(",")
            ]

        # Refresh token settings - only set if not already configured
        if not self.refresh_token_endpoint:
            self.refresh_token_endpoint = os.getenv("REFRESH_TOKEN_ENDPOINT")

        # Cache settings
        cache_ttl = os.getenv("JWT_CACHE_TTL")
        if cache_ttl:
            try:
                self.jwt_cache_ttl = int(cache_ttl)
            except ValueError:
                logger.warning(f"Invalid JWT_CACHE_TTL: {cache_ttl}, using default")

    def set_refresh_token_handlers(
        self,
        request_builder: Callable[[str], dict],
        response_parser: Callable[[dict], Optional[str]],
        pattern_detector: Callable[[str], bool] = None,
    ):
        """Set handlers for refresh token conversion.

        This method configures the handlers needed for converting refresh
        tokens to JWT tokens. These handlers define how to build requests
        to the refresh token endpoint and how to parse the responses.

        Args:
            request_builder: Function that takes a refresh token and returns
                the request payload for the refresh token endpoint.
            response_parser: Function that takes the response data and returns
                the JWT token, or None if parsing fails.
            pattern_detector: Optional function that takes a token and returns
                True if it matches the refresh token pattern. If None, a
                default pattern detector is used.

        Examples:
            >>> def build_request(token):
            ...     return {"refresh_token": token}

            >>> def parse_response(data):
            ...     return data.get("access_token")

            >>> def detect_pattern(token):
            ...     return ":" in token and len(token) > 20

            >>> config.set_refresh_token_handlers(
            ...     build_request, parse_response, detect_pattern
            ... )
        """
        self.refresh_token_request_builder = request_builder
        self.refresh_token_response_parser = response_parser
        self.refresh_token_pattern = pattern_detector

    def validate(self) -> bool:
        """Validate configuration.

        This method validates the authentication configuration to ensure
        all required settings are properly configured for the enabled
        features. It checks for logical consistency and completeness.

        Returns:
            True if the configuration is valid, False otherwise.

        Validation Rules:
        - If JWT validation is enabled, either signature verification or
          required claims must be configured
        - If refresh token conversion is enabled, the endpoint must be configured
        - Refresh token handlers can be auto-configured if missing

        Examples:
            >>> config = AuthConfig()
            >>> config.load_from_env()
            >>> if config.validate():
            ...     print("Configuration is valid")
            ... else:
            ...     print("Configuration has issues")
        """
        if not self.enabled:
            return True

        if self.jwt_validation_enabled:
            if not self.jwt_verify_signature and not self.jwt_required_claims:
                logger.warning(
                    "JWT validation enabled but no signature verification or required claims configured"
                )

        if self.refresh_token_enabled:
            if not self.refresh_token_endpoint:
                logger.error("Refresh token enabled but no endpoint configured")
                return False
            # Allow auto-configuration to handle missing handlers
            if (
                not self.refresh_token_request_builder
                or not self.refresh_token_response_parser
            ):
                logger.info(
                    "Refresh token handlers not configured - will be auto-configured"
                )

        return True


class JWTCache:
    """Thread-safe JWT cache with automatic cleanup.

    This class provides a thread-safe caching mechanism for JWT tokens
    to reduce API calls and improve performance. It automatically
    cleans up expired entries and provides efficient token storage.

    The cache provides:
    - Thread-safe operations using locks
    - Automatic expiration based on TTL
    - Periodic cleanup of expired entries
    - Efficient storage and retrieval

    Key Features:
    - Thread-safe operations for concurrent access
    - Automatic cleanup to prevent memory leaks
    - Configurable TTL and cleanup intervals
    - Efficient storage with minimal overhead

    Examples:
        >>> cache = JWTCache(ttl=3000, cleanup_interval=300)
        >>> cache.set("user123", "jwt_token_here")
        >>> token = cache.get("user123")
        >>> print(f"Retrieved token: {token is not None}")
    """

    def __init__(self, ttl: int = 3000, cleanup_interval: int = 300, auth_manager=None):
        self._cache: Dict[str, Tuple[str, float]] = {}
        self._lock = threading.Lock()
        self._ttl = ttl
        self._cleanup_interval = cleanup_interval
        self._last_cleanup = 0
        self._auth_manager = (
            auth_manager  # Optional AuthManager for TokenStore integration
        )

    def get(self, key: str) -> Optional[str]:
        """Get JWT from cache if not expired.

        This method retrieves a JWT token from the cache if it exists
        and has not expired. It automatically performs cleanup of
        expired entries during retrieval operations.

        Args:
            key: The cache key for the JWT token.

        Returns:
            The JWT token if found and not expired, None otherwise.

        Examples:
            >>> cache = JWTCache()
            >>> token = cache.get("user123")
            >>> if token:
            ...     print("Token found and valid")
            ... else:
            ...     print("Token not found or expired")
        """
        # Try to get from TokenStore if AuthManager is available
        if self._auth_manager and hasattr(self._auth_manager, "get_token"):
            import asyncio

            # Parse key to extract provider and identity info
            # Key format: "provider:identity:region" or similar
            parts = key.split(":")
            if len(parts) >= 2:
                _provider_type = parts[0]
                _identity_id = parts[1]
                _region = parts[2] if len(parts) > 2 else None

                # Skip async TokenStore lookup in sync context
                # Creating event loops here is problematic for Python 3.13
                try:
                    asyncio.get_running_loop()
                    # In async context, but skip lookup to avoid blocking
                    logger.debug("In async context - deferring TokenStore lookup")
                except RuntimeError:
                    # Not in async context - cannot safely perform async operations
                    # Token will be retrieved from local cache only
                    logger.debug("Not in async context - TokenStore lookup unavailable")

        # Fall back to local cache
        now = time.time()

        # Clean up expired entries periodically
        if now - self._last_cleanup > self._cleanup_interval:
            self._cleanup(now)
            self._last_cleanup = now

        with self._lock:
            if key in self._cache:
                jwt_token, expiry_time = self._cache[key]
                if now < expiry_time:
                    return jwt_token
                else:
                    # Remove expired entry
                    del self._cache[key]
                    logger.debug(f"Removed expired cache entry for key: {key[:20]}...")

        return None

    def set(self, key: str, jwt_token: str) -> None:
        """Cache JWT with expiration.

        This method stores a JWT token in the cache with an expiration
        time based on the configured TTL. The token will be automatically
        removed when it expires.

        Args:
            key: The cache key for the JWT token.
            jwt_token: The JWT token to cache.

        Examples:
            >>> cache = JWTCache(ttl=3000)
            >>> cache.set("user123", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
            >>> print("Token cached successfully")
        """
        now = time.time()
        expiry_time = now + self._ttl

        # Store in TokenStore if AuthManager is available
        if self._auth_manager and hasattr(self._auth_manager, "set_token"):
            import asyncio

            from ..auth.token_store import TokenKind

            # Parse key to extract provider and identity info
            parts = key.split(":")
            if len(parts) >= 2:
                provider_type = parts[0]
                identity_id = parts[1]
                region = parts[2] if len(parts) > 2 else None

                expires_at = datetime.now(timezone.utc) + timedelta(seconds=self._ttl)

                try:
                    # Check if we're in an async context
                    try:
                        asyncio.get_running_loop()
                        # We're in async context, schedule the update
                        asyncio.create_task(
                            self._auth_manager.set_token(
                                provider_type=provider_type,
                                identity_id=identity_id,
                                token_kind=TokenKind.PROVIDER_JWT,
                                token=jwt_token,
                                expires_at=expires_at,
                                metadata={"cache_key": key},
                                region=region,
                            )
                        )
                    except RuntimeError:
                        # Not in async context - defer the update
                        logger.debug(
                            "Token store update deferred - not in async context"
                        )
                except Exception as e:
                    logger.debug(f"Failed to store token in TokenStore: {e}")

        # Also store in local cache for fast access
        with self._lock:
            self._cache[key] = (jwt_token, expiry_time)

    def _cleanup(self, now: float) -> None:
        """Remove expired cache entries.

        This method removes all expired cache entries to prevent memory
        leaks and maintain cache efficiency. It is called automatically
        during cache operations.

        Args:
            now: The current timestamp for expiration comparison.

        Examples:
            >>> cache = JWTCache()
            >>> # Cleanup is called automatically during get() operations
            >>> cache._cleanup(time.time())  # Manual cleanup if needed
        """
        with self._lock:
            expired_keys = [
                key
                for key, (_, expiry_time) in self._cache.items()
                if now >= expiry_time
            ]
            for key in expired_keys:
                del self._cache[key]

            if expired_keys:
                logger.info(f"Cleaned up {len(expired_keys)} expired JWT cache entries")


class RefreshTokenMiddleware(Middleware):
    """Middleware to convert refresh tokens to JWT tokens with caching.

    This middleware intercepts requests containing refresh tokens and
    converts them to JWT tokens using configured endpoints. It provides
    caching to reduce API calls and improve performance.

    The middleware provides:
    - Refresh token pattern detection
    - Token conversion using configured endpoints
    - JWT caching for performance optimization
    - Context-safe JWT storage for other middleware
    - Comprehensive error handling and logging

    Key Features:
    - Automatic refresh token detection using pattern matching
    - Configurable request building and response parsing
    - JWT caching to reduce API calls
    - Context-safe token sharing with JWT middleware
    - Comprehensive error handling and logging

    Examples:
        >>> config = AuthConfig()
        >>> config.refresh_token_enabled = True
        >>> config.refresh_token_endpoint = "https://api.example.com/refresh"
        >>> middleware = RefreshTokenMiddleware(config)
    """

    def __init__(self, config: AuthConfig, auth_manager: Optional[Any] = None):
        super().__init__()
        self.config = config
        self.auth_manager = auth_manager
        self.logger = logging.getLogger(f"{__name__}.RefreshTokenMiddleware")
        self._jwt_cache = JWTCache(
            config.jwt_cache_ttl, config.cache_cleanup_interval, auth_manager
        )

    async def on_request(self, context: MiddlewareContext, call_next):
        """Convert refresh tokens to JWT tokens if needed.

        This method intercepts incoming requests and checks for refresh
        tokens in the Authorization header. If a refresh token is detected,
        it converts it to a JWT token and stores it in context-safe storage
        for use by other middleware components.

        Args:
            context: The FastMCP middleware context.
            call_next: The next middleware in the chain.

        Returns:
            The result of the next middleware in the chain.

        Examples:
            >>> # This method is called automatically by FastMCP
            >>> # when requests are processed through the middleware chain
        """
        if not self.config.enabled or not self.config.refresh_token_enabled:
            return await call_next(context)

        try:
            # Get headers from the context if available
            auth_header = ""
            if context.fastmcp_context:
                request = context.fastmcp_context.request_context.request
                if request and hasattr(request, "headers"):
                    auth_header = request.headers.get("authorization", "")

            if not auth_header:
                return await call_next(context)

            # Extract token more robustly - handle case variations and extra whitespace
            parts = auth_header.split(" ", 1)
            if len(parts) != 2 or parts[0].lower() != "bearer":
                return await call_next(context)

            token = parts[1].strip()  # Remove any leading/trailing whitespace

            # Check if this matches the refresh token pattern
            if self.config.refresh_token_pattern and self.config.refresh_token_pattern(
                token
            ):
                self.logger.debug("Detected refresh token format, checking cache...")

                # If auth_manager with OpenBridge provider is available, update its refresh token
                if self.auth_manager and hasattr(self.auth_manager, "provider"):
                    provider = self.auth_manager.provider
                    if hasattr(provider, "set_refresh_token"):
                        self.logger.debug(
                            "Setting refresh token in OpenBridge provider"
                        )
                        provider.set_refresh_token(token)

                jwt_token = await self._get_cached_or_convert_jwt(token)
                if jwt_token:
                    self.logger.debug("JWT token ready (cached or converted)")
                    # Store the JWT in context-safe storage for the JWT middleware to use
                    jwt_token_var.set(jwt_token)
                else:
                    self.logger.error("Failed to convert refresh token to JWT")
            else:
                self.logger.debug(
                    "Token does not match refresh token pattern - skipping conversion"
                )

        except Exception as e:
            self.logger.error(f"RefreshTokenMiddleware error: {e}")

        return await call_next(context)

    async def _get_cached_or_convert_jwt(self, refresh_token: str) -> Optional[str]:
        """Get JWT from cache or convert refresh token to JWT.

        This method first checks the cache for an existing JWT token
        for the given refresh token. If not found or expired, it
        converts the refresh token to a JWT token using the configured
        endpoint and caches the result.

        Args:
            refresh_token: The refresh token to convert or lookup.

        Returns:
            The JWT token if conversion/lookup is successful, None otherwise.

        Examples:
            >>> jwt_token = await middleware._get_cached_or_convert_jwt("refresh_token_here")
            >>> if jwt_token:
            ...     print("JWT token obtained successfully")
        """
        # Check cache first
        cached_jwt = self._jwt_cache.get(refresh_token)
        if cached_jwt:
            self.logger.debug("Using cached JWT token")
            return cached_jwt

        # Convert refresh token to JWT
        self.logger.info("Converting refresh token to JWT (cache miss)...")
        jwt_token = await self._convert_refresh_to_jwt(refresh_token)

        if jwt_token:
            # Cache the JWT
            self._jwt_cache.set(refresh_token, jwt_token)
            self.logger.info("Cached new JWT token")

        return jwt_token

    async def _convert_refresh_to_jwt(self, refresh_token: str) -> Optional[str]:
        """Convert refresh token to JWT using configured endpoint.

        This method converts a refresh token to a JWT token by making
        a request to the configured refresh token endpoint. It uses
        the configured request builder and response parser to handle
        the conversion process.

        Args:
            refresh_token: The refresh token to convert.

        Returns:
            The JWT token if conversion is successful, None otherwise.

        Raises:
            httpx.HTTPError: If the HTTP request to the refresh endpoint fails.
            Exception: If any other error occurs during conversion.

        Examples:
            >>> jwt_token = await middleware._convert_refresh_to_jwt("refresh_token_here")
            >>> if jwt_token:
            ...     print("Token converted successfully")
        """
        try:
            # Build request using configured builder
            payload = self.config.refresh_token_request_builder(refresh_token)

            # Get shared HTTP client
            client = await get_http_client()

            response = await client.post(
                self.config.refresh_token_endpoint,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=10.0,
            )
            response.raise_for_status()

            # Parse response using configured parser
            response_data = response.json()
            jwt_token = self.config.refresh_token_response_parser(response_data)

            if jwt_token:
                self.logger.debug("Successfully converted refresh token to JWT")
                return jwt_token
            else:
                self.logger.error("Response parser returned no JWT token")
                return None

        except httpx.HTTPError as e:
            self.logger.error(f"Failed to convert refresh token: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Error converting refresh token: {e}")
            return None


class JWTAuthenticationMiddleware(Middleware):
    """Middleware to validate JWT authentication with comprehensive error handling.

    This middleware validates JWT tokens in incoming requests and provides
    comprehensive error handling and logging. It supports both signature
    verification and claim-based validation modes.

    The middleware provides:
    - JWT token extraction from Authorization headers
    - Signature verification using public keys or JWKS
    - Claim validation (issuer, audience, expiration)
    - OpenBridge-specific validation (user_id, account_id)
    - Context-safe claim storage for application use
    - Comprehensive error handling and detailed logging

    Key Features:
    - Support for both signature verification and claim-only validation
    - JWKS integration for dynamic public key retrieval
    - OpenBridge-specific claim validation
    - Context-safe claim storage using contextvars
    - Comprehensive error handling with detailed logging
    - Token corruption detection and cleanup attempts

    Examples:
        >>> config = AuthConfig()
        >>> config.jwt_validation_enabled = True
        >>> config.jwt_verify_signature = True
        >>> middleware = JWTAuthenticationMiddleware(config)
    """

    def __init__(self, config: AuthConfig):
        super().__init__()
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.JWTAuthenticationMiddleware")

    async def on_request(self, context: MiddlewareContext, call_next):
        """Validate JWT authentication for all requests.

        This method intercepts incoming requests and validates JWT tokens
        from either context-safe storage (set by RefreshTokenMiddleware)
        or Authorization headers. It stores validated claims in context
        for use by other parts of the application.

        Args:
            context: The FastMCP middleware context.
            call_next: The next middleware in the chain.

        Returns:
            The result of the next middleware in the chain.

        Raises:
            ToolError: If authentication fails or is missing.

        Examples:
            >>> # This method is called automatically by FastMCP
            >>> # when requests are processed through the middleware chain
        """
        if not self.config.enabled or not self.config.jwt_validation_enabled:
            self.logger.debug("Authentication disabled, skipping validation")
            return await call_next(context)

        try:
            # Check for JWT set by RefreshTokenMiddleware in context-safe storage
            jwt_token = jwt_token_var.get()
            if jwt_token:
                token = jwt_token
                self.logger.info("Using JWT from context-safe storage")
                # Clear the token from context after use
                jwt_token_var.set(None)
            else:
                # Get token from headers via context
                auth_header = ""
                if context.fastmcp_context:
                    request = context.fastmcp_context.request_context.request
                    if request and hasattr(request, "headers"):
                        auth_header = request.headers.get("authorization", "")

                self.logger.info(
                    f"JWT middleware - Authorization header present: {bool(auth_header)}"
                )

                if not auth_header:
                    self.logger.warning(
                        "JWT middleware - Missing Authorization header, rejecting request"
                    )
                    raise ToolError(
                        "Authentication required: Missing Authorization header"
                    )

                # Extract token more robustly - handle case variations and extra whitespace
                self.logger.debug(
                    f"Authorization header: {sanitize_string(auth_header)}"
                )
                parts = auth_header.split(" ", 1)
                if len(parts) != 2 or parts[0].lower() != "bearer":
                    self.logger.warning(
                        f"JWT middleware - Invalid Authorization header format: {sanitize_string(auth_header)}"
                    )
                    raise ToolError(
                        "Authentication required: Invalid Authorization header format"
                    )

                token = parts[1].strip()  # Remove any leading/trailing whitespace
                self.logger.debug(f"Extracted token (length: {len(token)}, type: JWT)")

            # Validate the JWT token and store claims in context
            claims = await self._validate_jwt_token(token)
            if claims:
                self.logger.info("JWT token validation successful")
                # Store validated claims in context for other parts of the application
                jwt_claims_var.set(claims)
                return await call_next(context)
            else:
                self.logger.error("JWT token validation failed")
                raise ToolError("Invalid authentication token")

        except ToolError:
            raise
        except Exception as e:
            self.logger.error(f"Authentication error: {e}")
            raise ToolError("Authentication failed")

    async def _validate_jwt_token(self, token: str) -> Optional[dict]:
        """Validate JWT token and return claims if valid.

        This method validates a JWT token using either signature verification
        or claim-only validation based on the configuration. It handles
        different validation modes and provides comprehensive error handling.

        Args:
            token: The JWT token to validate.

        Returns:
            The decoded claims if validation is successful, None otherwise.

        Examples:
            >>> claims = await middleware._validate_jwt_token("jwt_token_here")
            >>> if claims:
            ...     print(f"User ID: {claims.get('user_id')}")
        """
        try:
            if self.config.jwt_verify_signature:
                return await self._validate_jwt_with_signature(token)
            else:
                return await self._validate_jwt_without_signature(token)
        except Exception as e:
            self.logger.warning(f"JWT decode failed: {e}")
            return None

    async def _validate_jwt_with_signature(self, token: str) -> Optional[dict]:
        """Validate JWT token with signature verification and return claims.

        This method validates a JWT token using cryptographic signature
        verification. It retrieves the public key from configured sources
        and validates the token's signature, issuer, audience, and expiration.

        Args:
            token: The JWT token to validate with signature verification.

        Returns:
            The decoded claims if signature verification is successful, None otherwise.

        Raises:
            jwt.ExpiredSignatureError: If the token has expired.
            jwt.InvalidIssuerError: If the issuer validation fails.
            jwt.InvalidAudienceError: If the audience validation fails.
            jwt.InvalidSignatureError: If the signature validation fails.

        Examples:
            >>> claims = await middleware._validate_jwt_with_signature("jwt_token_here")
            >>> if claims:
            ...     print("Signature verification successful")
        """
        try:
            # Get public key
            public_key = await self._get_public_key(token)
            if not public_key:
                self.logger.warning("No public key available for JWT validation")
                return None

            # Prepare decode options
            decode_options = {
                "verify_signature": True,
                "verify_exp": True,
                "verify_iss": self.config.jwt_verify_iss,
                "verify_aud": self.config.jwt_verify_aud,
            }

            # Only validate audience if explicitly configured (like FastMCP BearerAuthProvider)
            decode_kwargs = {
                "token": token,
                "key": public_key,
                "algorithms": ["RS256", "ES256", "HS256"],
                "options": decode_options,
            }

            # Add audience only if configured and verification is enabled
            if self.config.jwt_audience and self.config.jwt_verify_aud:
                decode_kwargs["audience"] = self.config.jwt_audience
            elif self.config.jwt_verify_aud:
                # If audience verification is enabled but no audience is configured, disable it
                decode_options["verify_aud"] = False
                self.logger.debug(
                    "Audience verification disabled - no audience configured"
                )

            # Decode with signature verification
            payload = jwt.decode(**decode_kwargs)

            # Validate required claims
            for claim in self.config.jwt_required_claims:
                if claim not in payload:
                    self.logger.warning(f"Missing required claim: {claim}")
                    return None

            return payload

        except jwt.ExpiredSignatureError:
            self.logger.warning("JWT token is expired")
            return None
        except jwt.InvalidIssuerError:
            self.logger.warning("JWT issuer validation failed")
            return None
        except jwt.InvalidAudienceError:
            self.logger.warning("JWT audience validation failed")
            return None
        except jwt.InvalidSignatureError:
            self.logger.warning("JWT signature validation failed")
            return None
        except Exception as e:
            self.logger.warning(f"JWT validation error: {e}")
            return None

    async def _validate_jwt_without_signature(self, token: str) -> Optional[dict]:
        """Validate JWT token without signature verification (OpenBridge style) and return claims.

        This method validates a JWT token without cryptographic signature
        verification, focusing on claim validation and OpenBridge-specific
        requirements. It handles token corruption detection and cleanup attempts.

        Args:
            token: The JWT token to validate without signature verification.

        Returns:
            The decoded claims if validation is successful, None otherwise.

        Examples:
            >>> claims = await middleware._validate_jwt_without_signature("jwt_token_here")
            >>> if claims:
            ...     print(f"OpenBridge validation successful - User: {claims.get('user_id')}")
        """
        try:
            # Clean the token - remove any whitespace or encoding issues
            token = token.strip()

            # Debug token format - add more detailed logging
            self.logger.debug(f"Validating JWT token (length: {len(token)})")

            # Check for common corruption patterns
            if token.startswith("Bearer "):
                self.logger.error(
                    "Token still has 'Bearer ' prefix - extraction failed!"
                )
                token = token[7:].strip()

            if " " in token:
                self.logger.error("Token contains whitespace - may be corrupted")
                self.logger.error(
                    f"Whitespace positions: {[i for i, c in enumerate(token) if c == ' ']}"
                )
                token = token.replace(" ", "")

            if "\n" in token or "\r" in token:
                self.logger.error("Token contains newlines - may be corrupted")
                token = token.replace("\n", "").replace("\r", "")

            # Try to decode the token parts first to understand the structure
            try:
                parts = token.split(".")
                if len(parts) != 3:
                    self.logger.error(
                        f"Token doesn't have 3 parts! Found {len(parts)} parts"
                    )
                    return None

                self.logger.debug(
                    f"Token has 3 parts: header({len(parts[0])}), payload({len(parts[1])}), signature({len(parts[2])})"
                )
            except Exception as e:
                self.logger.error(f"Failed to split token: {e}")
                return None

            # Decode without signature verification
            payload = jwt.decode(token, options={"verify_signature": False})

            # Check if token is expired using expires_at (OpenBridge format)
            expires_at = payload.get("expires_at")
            if expires_at:
                try:
                    exp_time = datetime.fromtimestamp(
                        float(expires_at), tz=timezone.utc
                    )
                    if datetime.now(timezone.utc) > exp_time:
                        self.logger.warning("JWT token is expired")
                        return None
                except (ValueError, TypeError):
                    self.logger.warning(f"Invalid expires_at format: {expires_at}")
                    return None

            # Validate OpenBridge-specific claims (user_id, account_id)
            user_id = payload.get("user_id")
            account_id = payload.get("account_id")

            if not user_id or not account_id:
                self.logger.warning(
                    "JWT missing required OpenBridge fields (user_id, account_id)"
                )
                return None

            self.logger.info(
                f"OpenBridge token validated - User: {user_id}, Account: {account_id}"
            )
            return payload

        except jwt.DecodeError as e:
            self.logger.warning(f"JWT decode error: {e}")
            # Try to provide more specific error information
            if "Invalid header padding" in str(e):
                self.logger.error(
                    "JWT header padding error - token may be corrupted or improperly formatted"
                )
                self.logger.error(f"Original token: {sanitize_string(token)}")

                # Try to clean the token and retry
                try:
                    # Remove any potential encoding issues
                    cleaned_token = (
                        token.strip()
                        .replace(" ", "")
                        .replace("\n", "")
                        .replace("\r", "")
                    )
                    if cleaned_token != token:
                        self.logger.info("Attempting to decode cleaned token")
                        self.logger.info(
                            f"Cleaned token: {sanitize_string(cleaned_token)}"
                        )
                        payload = jwt.decode(
                            cleaned_token, options={"verify_signature": False}
                        )
                        self.logger.info("Cleaned token decoded successfully")
                        return payload
                except Exception as cleanup_error:
                    self.logger.error(
                        f"Failed to clean and decode token: {cleanup_error}"
                    )

                # Try to analyze the token structure
                try:
                    parts = token.split(".")
                    if len(parts) >= 1:
                        self.logger.error(f"Header part: {sanitize_string(parts[0])}")
                        if len(parts) >= 2:
                            self.logger.error(
                                f"Payload part: {sanitize_string(parts[1])}"
                            )
                except Exception as analyze_error:
                    self.logger.error(
                        f"Failed to analyze token structure: {analyze_error}"
                    )

            return None
        except Exception as e:
            self.logger.warning(f"JWT validation error: {e}")
            return None

    async def _get_public_key(self, token: str) -> Optional[str]:
        """Get public key for JWT validation.

        This method retrieves the public key needed for JWT signature
        verification. It supports both static public keys and dynamic
        key retrieval from JWKS endpoints.

        Args:
            token: The JWT token to extract key information from.

        Returns:
            The public key in PEM format if available, None otherwise.

        Examples:
            >>> public_key = await middleware._get_public_key("jwt_token_here")
            >>> if public_key:
            ...     print("Public key retrieved successfully")
        """
        if self.config.jwt_public_key:
            return self.config.jwt_public_key

        if self.config.jwt_jwks_uri:
            try:
                # Decode header to get key ID
                header = jwt.get_unverified_header(token)
                kid = header.get("kid")

                if not kid:
                    self.logger.warning("No key ID in JWT header")
                    return None

                # Get shared HTTP client
                client = await get_http_client()

                # Fetch JWKS
                response = await client.get(self.config.jwt_jwks_uri, timeout=10.0)
                response.raise_for_status()
                jwks = response.json()

                # Find the key
                for key in jwks.get("keys", []):
                    if key.get("kid") == kid:
                        return self._jwk_to_pem(key)

                self.logger.warning(f"Key ID {kid} not found in JWKS")
                return None

            except httpx.HTTPError as e:
                self.logger.error(f"Failed to fetch JWKS: {e}")
                return None
            except Exception as e:
                self.logger.error(f"Error processing JWKS: {e}")
                return None

        return None

    def _jwk_to_pem(self, jwk_key: dict) -> Optional[str]:
        """Convert JWK to PEM format.

        This method converts a JSON Web Key (JWK) to PEM format for
        use in JWT signature verification. It currently supports RSA keys.

        Args:
            jwk_key: The JWK key dictionary to convert.

        Returns:
            The public key in PEM format if conversion is successful, None otherwise.

        Examples:
            >>> jwk = {"kty": "RSA", "n": "...", "e": "..."}
            >>> pem_key = middleware._jwk_to_pem(jwk)
            >>> if pem_key:
            ...     print("JWK converted to PEM successfully")
        """
        try:
            # This is a simplified conversion - in production you'd want a proper JWK library
            if jwk_key.get("kty") == "RSA":
                from cryptography.hazmat.primitives import serialization
                from cryptography.hazmat.primitives.asymmetric import rsa

                n = int.from_bytes(jwt.utils.base64url_decode(jwk_key["n"]), "big")
                e = int.from_bytes(jwt.utils.base64url_decode(jwk_key["e"]), "big")

                public_key = rsa.RSAPublicNumbers(e, n).public_key()
                pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                return pem.decode("utf-8")

        except Exception as e:
            self.logger.error(f"Error converting JWK to PEM: {e}")

        return None


# Utility functions for accessing JWT data from context
def get_current_jwt() -> Optional[str]:
    """Get JWT token for current request context.

    This function retrieves the JWT token from the current request context
    using context-safe storage. It provides access to the JWT token
    for other parts of the application that need it.

    :return: The JWT token for the current request context, or None if not available
    :rtype: Optional[str]

    .. example::
       >>> jwt_token = get_current_jwt()
       >>> if jwt_token:
       ...     print("JWT token available in current context")
    """
    return jwt_token_var.get()


def get_current_claims() -> Optional[dict]:
    """Get JWT claims for current request context.

    This function retrieves the validated JWT claims from the current
    request context using context-safe storage. It provides access to
    user information and other claims for application logic.

    :return: The JWT claims dictionary for the current request context, or None if not available
    :rtype: Optional[dict]

    .. example::
       >>> claims = get_current_claims()
       >>> if claims:
       ...     print(f"User ID: {claims.get('user_id')}")
       ...     print(f"Account ID: {claims.get('account_id')}")
    """
    return jwt_claims_var.get()


def create_auth_middleware(
    config: Optional[AuthConfig] = None,
    refresh_token_middleware: bool = True,
    jwt_middleware: bool = True,
    auth_manager: Optional[Any] = None,
) -> list:
    """Create authentication middleware chain.

    This function creates a complete authentication middleware chain
    with optional refresh token conversion and JWT validation. It
    supports auto-configuration for common providers like OpenBridge.

    The function automatically detects provider types and configures
    appropriate handlers for refresh token conversion and JWT validation.
    It supports OpenBridge, generic JSON:API, and custom configurations.

    :param config: Optional AuthConfig instance. If None, creates a new config and loads settings from environment variables
    :type config: Optional[AuthConfig]
    :param refresh_token_middleware: Whether to include refresh token conversion middleware
    :type refresh_token_middleware: bool
    :param jwt_middleware: Whether to include JWT validation middleware
    :type jwt_middleware: bool
    :param auth_manager: Optional AuthManager instance for token store integration
    :type auth_manager: Optional[Any]
    :return: A list of middleware instances ready for use with FastMCP
    :rtype: list

    .. example::
       >>> # Auto-configure from environment
       >>> middleware = create_auth_middleware()

       >>> # Use specific configuration
       >>> config = AuthConfig()
       >>> config.load_from_env()
       >>> middleware = create_auth_middleware(config)

       >>> # JWT validation only
       >>> middleware = create_auth_middleware(
       ...     refresh_token_middleware=False, jwt_middleware=True
       ... )
    """
    if not config:
        config = AuthConfig()
        config.load_from_env()

        # Auto-configure OpenBridge if the endpoint is detected
        if config.refresh_token_enabled and config.refresh_token_endpoint:
            # Validate hostname is legitimate OpenBridge domain
            from urllib.parse import urlparse
            parsed_endpoint = urlparse(config.refresh_token_endpoint)
            endpoint_host = (parsed_endpoint.hostname or "").lower()
            is_openbridge = endpoint_host.endswith(".openbridge.io") or endpoint_host == "openbridge.io"
            if is_openbridge:
                logger.info("Auto-configuring OpenBridge authentication")
                # Use OpenBridge-specific configuration
                config = create_openbridge_config()
                # Override with environment variables but preserve auto-configured handlers
                config.load_from_env()
            elif not config.refresh_token_request_builder:
                # Auto-configure generic JSON:API if no handlers are set
                logger.info("Auto-configuring generic JSON:API authentication")
                config = create_json_api_refresh_token_config(
                    endpoint_url=config.refresh_token_endpoint,
                    token_type_name=os.getenv("JSON_API_TOKEN_TYPE_NAME", "APIAuth"),
                    required_claims=config.jwt_required_claims or ["user_id"],
                    verify_signature=config.jwt_verify_signature,
                )
                # Override with environment variables but preserve auto-configured handlers
                config.load_from_env()

    if not config.validate():
        logger.error("Invalid authentication configuration")
        return []

    middleware = []

    # Add refresh token middleware first (converts refresh tokens to JWTs)
    if refresh_token_middleware and config.refresh_token_enabled:
        middleware.append(RefreshTokenMiddleware(config, auth_manager))
        logger.info("Added RefreshTokenMiddleware")

    # Add JWT authentication middleware (validates JWTs)
    if jwt_middleware and config.jwt_validation_enabled:
        middleware.append(JWTAuthenticationMiddleware(config))
        logger.info("Added JWTAuthenticationMiddleware")

    logger.info(f"Created {len(middleware)} middleware components")
    return middleware


def create_json_api_refresh_token_config(
    endpoint_url: str,
    token_type_name: str,
    required_claims: list[str],
    verify_signature: bool = True,
) -> AuthConfig:
    """Create configuration for JSON:API style refresh token endpoints.

    This function creates a pre-configured AuthConfig for JSON:API
    style refresh token endpoints with standard request/response
    patterns and handlers.

    The configuration includes standard JSON:API request builders,
    response parsers, and token pattern detection for automatic
    refresh token handling.

    :param endpoint_url: The refresh token endpoint URL
    :type endpoint_url: str
    :param token_type_name: The JSON:API resource type name for tokens
    :type token_type_name: str
    :param required_claims: List of required JWT claims for validation
    :type required_claims: list[str]
    :param verify_signature: Whether to verify JWT signatures
    :type verify_signature: bool
    :return: A configured AuthConfig instance for JSON:API refresh tokens
    :rtype: AuthConfig

    .. example::
       >>> config = create_json_api_refresh_token_config(
       ...     endpoint_url="https://api.example.com/auth/refresh",
       ...     token_type_name="APIAuth",
       ...     required_claims=["user_id", "account_id"]
       ... )
       >>> middleware = create_auth_middleware(config)
    """
    config = AuthConfig()
    config.enabled = True
    config.refresh_token_enabled = True
    config.jwt_validation_enabled = True
    config.refresh_token_endpoint = endpoint_url
    config.jwt_required_claims = required_claims
    config.jwt_verify_signature = verify_signature

    # JSON:API request builder
    def request_builder(refresh_token: str) -> dict:
        return {
            "data": {
                "type": token_type_name,
                "attributes": {"refresh_token": refresh_token},
            }
        }

    # JSON:API response parser
    def response_parser(response_data: dict) -> Optional[str]:
        try:
            return response_data.get("data", {}).get("attributes", {}).get("token")
        except Exception:
            return None

    # Pattern detector for refresh tokens (simple heuristic)
    def pattern_detector(token: str) -> bool:
        # OpenBridge refresh tokens typically contain a colon
        return ":" in token and len(token) > 20

    config.set_refresh_token_handlers(
        request_builder, response_parser, pattern_detector
    )
    return config


def create_openbridge_config() -> AuthConfig:
    """Create configuration for OpenBridge authentication.

    This function creates a pre-configured AuthConfig specifically
    for OpenBridge authentication with the correct endpoint, token
    type, and validation settings.

    The configuration automatically detects the OpenBridge authentication
    base URL from environment variables and sets up appropriate handlers
    for refresh token conversion and JWT validation.

    :return: A configured AuthConfig instance for OpenBridge authentication
    :rtype: AuthConfig

    .. example::
       >>> config = create_openbridge_config()
       >>> middleware = create_auth_middleware(config)

    .. note::
       The configuration includes:

       - OpenBridge refresh token endpoint
       - APIAuth token type
       - user_id and account_id required claims
       - Signature verification disabled (tokens trusted from API)
    """
    # Build endpoint from env, with explicit REFRESH_TOKEN_ENDPOINT taking precedence
    auth_base = os.getenv(
        "OPENBRIDGE_AUTH_BASE_URL", "https://authentication.api.openbridge.io"
    ).rstrip("/")
    endpoint_url = os.getenv("REFRESH_TOKEN_ENDPOINT", f"{auth_base}/auth/api/refresh")

    config = create_json_api_refresh_token_config(
        endpoint_url=endpoint_url,
        token_type_name="APIAuth",
        required_claims=["user_id", "account_id"],
        verify_signature=False,  # OpenBridge JWTs are trusted from the API, no public key available
    )

    # OpenBridge-specific settings
    config.jwt_verify_iss = False  # Don't validate issuer for OpenBridge
    config.jwt_verify_aud = False  # Don't validate audience for OpenBridge

    return config


def create_auth0_config(domain: str, audience: str) -> AuthConfig:
    """Create Auth0 configuration.

    This function creates a pre-configured AuthConfig for Auth0
    authentication with the correct issuer, audience, and JWKS
    endpoint settings.

    The configuration sets up standard Auth0 JWT validation with
    public key retrieval from the JWKS endpoint and proper issuer
    and audience validation.

    :param domain: The Auth0 domain (e.g., "example.auth0.com")
    :type domain: str
    :param audience: The Auth0 API audience identifier
    :type audience: str
    :return: A configured AuthConfig instance for Auth0 authentication
    :rtype: AuthConfig

    .. example::
       >>> config = create_auth0_config(
       ...     domain="example.auth0.com",
       ...     audience="https://api.example.com"
       ... )
       >>> middleware = create_auth_middleware(config)

    .. note::
       The configuration includes:

       - Auth0 issuer URL
       - JWKS endpoint for public key retrieval
       - Audience validation
    """
    config = AuthConfig()
    config.load_from_env()
    config.jwt_issuer = f"https://{domain}/"
    config.jwt_audience = audience
    config.jwt_jwks_uri = f"https://{domain}/.well-known/jwks.json"
    return config


async def get_auth_info() -> Dict[str, Any]:
    """Get authentication information.

    This function retrieves comprehensive information about the current
    authentication configuration, including enabled features and settings.
    Useful for debugging and monitoring authentication status.

    The returned information includes all key configuration settings
    loaded from environment variables and provides insight into the
    current authentication state.

    :return: A dictionary containing authentication configuration information
    :rtype: Dict[str, Any]

    Dictionary Keys:

    - enabled: Whether authentication is enabled
    - jwt_validation_enabled: Whether JWT validation is enabled
    - refresh_token_enabled: Whether refresh token conversion is enabled
    - jwt_issuer: Configured JWT issuer
    - jwt_audience: Configured JWT audience
    - jwt_verify_signature: Whether signature verification is enabled
    - jwt_verify_iss: Whether issuer verification is enabled
    - jwt_verify_aud: Whether audience verification is enabled
    - jwt_required_claims: List of required JWT claims

    .. example::
       >>> auth_info = await get_auth_info()
       >>> print(f"Authentication enabled: {auth_info['enabled']}")
       >>> print(f"JWT validation enabled: {auth_info['jwt_validation_enabled']}")
       >>> print(f"Required claims: {auth_info['jwt_required_claims']}")
    """
    config = AuthConfig()
    config.load_from_env()

    return {
        "enabled": config.enabled,
        "jwt_validation_enabled": config.jwt_validation_enabled,
        "refresh_token_enabled": config.refresh_token_enabled,
        "jwt_issuer": config.jwt_issuer,
        "jwt_audience": config.jwt_audience,
        "jwt_verify_signature": config.jwt_verify_signature,
        "jwt_verify_iss": config.jwt_verify_iss,
        "jwt_verify_aud": config.jwt_verify_aud,
        "jwt_required_claims": config.jwt_required_claims,
    }
