"""OAuth tools for integrated authentication flow."""

import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

import httpx
from fastmcp import Context
from pydantic import BaseModel, Field

from ..auth.oauth_state_store import get_oauth_state_store
from ..config.settings import Settings
from ..utils.region_config import RegionConfig

logger = logging.getLogger(__name__)


class OAuthState(BaseModel):
    """OAuth state tracking."""

    state: str = Field(description="OAuth state parameter for CSRF protection")
    auth_url: str = Field(description="Full authorization URL")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc) + timedelta(minutes=10)
    )
    completed: bool = Field(default=False)


class OAuthTokens(BaseModel):
    """OAuth token storage."""

    access_token: str
    refresh_token: str
    expires_in: int
    obtained_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def is_expired(self) -> bool:
        """Check if access token is expired."""
        expiry = self.obtained_at + timedelta(
            seconds=self.expires_in - 60
        )  # 60s buffer
        return datetime.now(timezone.utc) > expiry


class OAuthTools:
    """OAuth authentication tools for Amazon Ads API."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self.client_id = settings.ad_api_client_id
        self.client_secret = settings.ad_api_client_secret
        self.region = settings.amazon_ads_region
        # Use PORT env var (set at runtime) or settings.mcp_server_port or default to 9080
        import os

        port = os.getenv("PORT") or getattr(settings, "mcp_server_port", None) or 9080
        self.redirect_uri = f"http://localhost:{port}/auth/callback"

    async def start_oauth_flow(
        self,
        ctx: Context,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> Dict:
        """
        Start the OAuth authorization flow.

        Returns the authorization URL for the user to visit.
        """
        # Get secure state store
        state_store = get_oauth_state_store()

        # Build base authorization URL
        base_auth_url = (
            f"https://www.amazon.com/ap/oa"
            f"?client_id={self.client_id}"
            f"&scope=cpc_advertising:campaign_management"
            f"&response_type=code"
            f"&redirect_uri={self.redirect_uri}"
        )

        # Generate secure state with HMAC signature
        state = state_store.generate_state(
            auth_url=base_auth_url,
            user_agent=user_agent,
            ip_address=ip_address,
            ttl_minutes=10,
        )

        # Add state to auth URL
        auth_url = f"{base_auth_url}&state={state}"

        # Store OAuth state in context for status tracking
        oauth_state = OAuthState(
            state="[REDACTED]",  # Security: don't log OAuth state
            auth_url=auth_url,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        )
        await ctx.set_state("oauth_state", oauth_state.model_dump())

        return {
            "status": "success",
            "auth_url": auth_url,
            "message": "Visit the URL to authorize. The server will automatically handle the callback.",
            "expires_in_minutes": 10,
        }

    async def check_oauth_status(self, ctx: Context) -> Dict:
        """
        Check the current OAuth authentication status.

        Returns whether authentication is complete and token status.
        """
        # First check context for tokens
        tokens_data = await ctx.get_state("oauth_tokens")

        # If not in context, check persistent stores
        if not tokens_data:
            # Try secure token store first
            try:
                from ..auth.secure_token_store import get_secure_token_store

                secure_store = get_secure_token_store()

                refresh_entry = secure_store.get_token("oauth_refresh_token")
                access_entry = secure_store.get_token("oauth_access_token")

                if refresh_entry:
                    # Found tokens in secure store - reconstruct token object
                    tokens_data = {
                        "refresh_token": refresh_entry["value"],
                        "access_token": (access_entry["value"] if access_entry else ""),
                        "expires_in": 3600,
                        "obtained_at": refresh_entry.get(
                            "created_at", datetime.now(timezone.utc)
                        ).isoformat(),
                    }
                    # Cache in context for this request
                    await ctx.set_state("oauth_tokens", tokens_data)
            except Exception as e:
                logger.debug(f"Could not check secure store: {e}")

        # If still not found, check auth manager's token store
        if not tokens_data:
            try:
                from ..auth.manager import get_auth_manager
                from ..auth.token_store import TokenKind

                auth_manager = get_auth_manager()
                if auth_manager:
                    token_entry = await auth_manager.get_token(
                        provider_type="direct",
                        identity_id="direct-auth",
                        token_kind=TokenKind.REFRESH,
                    )
                    if token_entry:
                        # Found tokens - create minimal token data
                        tokens_data = {
                            "refresh_token": token_entry.value,
                            "access_token": "",
                            "expires_in": 0,
                            "obtained_at": datetime.now(timezone.utc).isoformat(),
                        }
                        # Cache in context
                        await ctx.set_state("oauth_tokens", tokens_data)
            except Exception as e:
                logger.debug(f"Could not check auth manager: {e}")

        # Check if callback has been received (legacy path)
        if hasattr(self, "_callback_tokens"):
            tokens = self._callback_tokens
            # Store in context for future use
            oauth_tokens = OAuthTokens(
                access_token=tokens["access_token"],
                refresh_token=tokens["refresh_token"],
                expires_in=tokens["expires_in"],
            )
            await ctx.set_state("oauth_tokens", oauth_tokens.model_dump())

            # Clear the callback tokens after storing
            delattr(self, "_callback_tokens")

            return {
                "authenticated": True,
                "status": "callback_received",
                "message": "Successfully authenticated via OAuth callback",
                "has_refresh_token": True,
                "scope": tokens["scope"],
            }

        # Check if we found tokens
        if tokens_data:
            # Tokens exist - user is authenticated
            tokens = OAuthTokens(**tokens_data)
            return {
                "authenticated": True,
                "status": "active",
                "has_refresh_token": bool(tokens.refresh_token),
                "access_token_expired": tokens.is_expired,
                "token_age_minutes": int(
                    (datetime.now(timezone.utc) - tokens.obtained_at).total_seconds()
                    / 60
                ),
            }
        else:
            # No tokens found - check OAuth flow state
            oauth_state = await ctx.get_state("oauth_state")
            if oauth_state:
                state_obj = OAuthState(**oauth_state)
                if state_obj.completed:
                    return {
                        "authenticated": False,
                        "status": "error",
                        "message": "OAuth flow completed but tokens not stored",
                    }
                elif datetime.now(timezone.utc) > state_obj.expires_at:
                    return {
                        "authenticated": False,
                        "status": "expired",
                        "message": "OAuth flow expired. Please start again.",
                    }
                else:
                    return {
                        "authenticated": False,
                        "status": "pending",
                        "message": "Waiting for authorization. Visit the auth URL.",
                        "auth_url": state_obj.auth_url,
                    }
            else:
                return {
                    "authenticated": False,
                    "status": "not_started",
                    "message": "OAuth flow not started. Use start_oauth_flow first.",
                }

    async def refresh_access_token(self, ctx: Context) -> Dict:
        """
        Manually refresh the access token using the stored refresh token.

        This is usually handled automatically by middleware.
        """
        # Try multiple sources for refresh token
        refresh_token = None

        # 1. Check context state (request-scoped)
        tokens_data = await ctx.get_state("oauth_tokens")
        if tokens_data:
            tokens = OAuthTokens(**tokens_data)
            refresh_token = tokens.refresh_token

        # 2. Check secure token store
        if not refresh_token:
            try:
                from ..auth.secure_token_store import get_secure_token_store

                secure_store = get_secure_token_store()
                token_entry = secure_store.get_token("oauth_refresh_token")
                if token_entry:
                    refresh_token = token_entry["value"]
            except Exception as e:
                logger.debug(f"Could not get from secure store: {e}")

        # 3. Check callback tokens
        if not refresh_token and hasattr(self, "_callback_tokens"):
            refresh_token = self._callback_tokens.get("refresh_token")

        # 4. Check auth manager's token store
        if not refresh_token:
            try:
                from ..auth.manager import get_auth_manager
                from ..auth.token_store import TokenKind

                auth_manager = get_auth_manager()
                if auth_manager:
                    token_entry = await auth_manager.get_token(
                        provider_type="direct",
                        identity_id="direct-auth",
                        token_kind=TokenKind.REFRESH,
                    )
                    if token_entry:
                        refresh_token = token_entry.value
            except Exception as e:
                logger.debug(f"Could not get token from auth manager: {e}")

        if not refresh_token:
            return {
                "status": "error",
                "message": "No refresh token found. Please complete OAuth flow first.",
            }

        # Create a temporary tokens object if we didn't have one
        if not tokens_data:
            tokens = OAuthTokens(
                access_token="",
                refresh_token=refresh_token,
                expires_in=0,
                obtained_at=datetime.now(timezone.utc),
            )

        # Exchange refresh token for new access token
        token_url = RegionConfig.get_oauth_endpoint(self.region)
        token_data = {
            "grant_type": "refresh_token",
            "refresh_token": tokens.refresh_token,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }

        # Use explicit timeout for OAuth token refresh
        timeout = httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=10.0)
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(token_url, data=token_data)

        if response.status_code == 200:
            token_response = response.json()

            # Update tokens
            tokens.access_token = token_response["access_token"]
            tokens.expires_in = token_response.get("expires_in", 3600)
            tokens.obtained_at = datetime.now(timezone.utc)

            # If a new refresh token was provided, update it
            if "refresh_token" in token_response:
                tokens.refresh_token = token_response["refresh_token"]

            # Store updated tokens in context
            await ctx.set_state("oauth_tokens", tokens.model_dump())

            # Store updated tokens securely
            try:
                from ..auth.secure_token_store import get_secure_token_store

                secure_store = get_secure_token_store()
                from datetime import timedelta

                secure_store.store_token(
                    token_id="oauth_refresh_token",
                    token_value=tokens.refresh_token,
                    token_type="refresh",
                    expires_at=datetime.now(timezone.utc) + timedelta(days=365),
                )

                logger.info("Updated refresh token in secure store")
            except Exception as e:
                logger.warning(f"Could not update secure store: {e}")

            # Update auth manager's token store
            try:
                from datetime import timedelta

                from ..auth.manager import get_auth_manager
                from ..auth.token_store import TokenKind

                auth_manager = get_auth_manager()
                if auth_manager:
                    # Store the new access token
                    expires_at = tokens.obtained_at + timedelta(
                        seconds=tokens.expires_in
                    )
                    await auth_manager.set_token(
                        provider_type="direct",
                        identity_id="direct-auth",
                        token_kind=TokenKind.ACCESS,
                        token=tokens.access_token,
                        expires_at=expires_at,
                        metadata={"token_type": "Bearer"},
                    )

                    # Update refresh token if changed
                    if "refresh_token" in token_response:
                        await auth_manager.set_token(
                            provider_type="direct",
                            identity_id="direct-auth",
                            token_kind=TokenKind.REFRESH,
                            token=tokens.refresh_token,
                            expires_at=datetime.now(timezone.utc) + timedelta(days=365),
                            metadata={},
                        )

                    logger.info("Updated tokens in auth manager store")
            except Exception as e:
                logger.warning(f"Could not update auth manager tokens: {e}")

            return {
                "status": "success",
                "message": "Access token refreshed successfully",
                "expires_in_seconds": tokens.expires_in,
            }
        else:
            return {
                "status": "error",
                "message": f"Failed to refresh token: {response.status_code}",
                "error": response.text,
            }

    async def clear_oauth_tokens(self, ctx: Context) -> Dict:
        """
        Clear stored OAuth tokens and state.

        Use this to reset authentication or switch accounts.
        """
        await ctx.set_state("oauth_tokens", None)
        await ctx.set_state("oauth_state", None)

        return {
            "status": "success",
            "message": "OAuth tokens and state cleared. Please run start_oauth_flow to authenticate again.",
        }

    async def handle_oauth_callback(
        self,
        code: str,
        state: str,
        ctx: Context,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> Dict:
        """
        Handle the OAuth callback from Amazon.

        This is called internally by the server when Amazon redirects back.
        """
        # Validate state using secure store
        state_store = get_oauth_state_store()
        is_valid, error_message = state_store.validate_state(
            state=state, user_agent=user_agent, ip_address=ip_address
        )

        if not is_valid:
            logger.warning(f"OAuth state validation failed: {error_message}")
            return {
                "status": "error",
                "message": error_message or "Invalid state parameter",
            }

        # Exchange code for tokens
        token_url = RegionConfig.get_oauth_endpoint(self.region)
        token_data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }

        # Use explicit timeout for OAuth callback token exchange
        timeout = httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=10.0)
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(token_url, data=token_data)

        if response.status_code == 200:
            token_response = response.json()

            # Store tokens
            tokens = OAuthTokens(
                access_token=token_response["access_token"],
                refresh_token=token_response.get("refresh_token", ""),
                expires_in=token_response.get("expires_in", 3600),
            )

            await ctx.set_state("oauth_tokens", tokens.model_dump())

            # Mark OAuth state as completed
            oauth_state = await ctx.get_state("oauth_state")
            if oauth_state:
                oauth_state["completed"] = True
                await ctx.set_state("oauth_state", oauth_state)

            # Store the refresh token securely
            try:
                from ..auth.secure_token_store import get_secure_token_store

                secure_store = get_secure_token_store()
                from datetime import datetime, timedelta, timezone

                secure_store.store_token(
                    token_id="oauth_refresh_token",
                    token_value=tokens.refresh_token,
                    token_type="refresh",
                    expires_at=datetime.now(timezone.utc) + timedelta(days=365),
                    metadata={"scope": token_response.get("scope")},
                )

                secure_store.store_token(
                    token_id="oauth_access_token",
                    token_value=tokens.access_token,
                    token_type="access",
                    expires_at=tokens.obtained_at
                    + timedelta(seconds=tokens.expires_in),
                    metadata={"token_type": "Bearer"},
                )

                logger.info("Stored tokens in secure token store")
            except Exception as e:
                logger.error(f"Failed to store tokens securely: {e}")
                # Continue without raising - tokens are stored in context at minimum

            # Store tokens in unified token store if auth manager available
            try:
                from datetime import datetime, timedelta, timezone

                from ..auth.manager import get_auth_manager
                from ..auth.token_store import TokenKind

                auth_manager = get_auth_manager()
                if auth_manager and hasattr(auth_manager, "set_token"):
                    # Store refresh token
                    await auth_manager.set_token(
                        provider_type="direct",
                        identity_id="direct-auth",
                        token_kind=TokenKind.REFRESH,
                        token=tokens.refresh_token,
                        expires_at=datetime.now(timezone.utc)
                        + timedelta(days=365),  # Long-lived
                        metadata={},
                    )

                    # Store access token
                    expires_at = tokens.obtained_at + timedelta(
                        seconds=tokens.expires_in
                    )
                    await auth_manager.set_token(
                        provider_type="direct",
                        identity_id="direct-auth",
                        token_kind=TokenKind.ACCESS,
                        token=tokens.access_token,
                        expires_at=expires_at,
                        metadata={"token_type": "Bearer"},
                    )
                    logger.info("Stored OAuth tokens in unified token store")

                    # Update the DirectProvider's refresh token
                    if (
                        auth_manager.provider
                        and auth_manager.provider.provider_type == "direct"
                    ):
                        auth_manager.provider.refresh_token = tokens.refresh_token
                        logger.info("Updated DirectProvider with new refresh token")
            except Exception as e:
                logger.error(f"Could not update auth manager: {e}")

            return {
                "status": "success",
                "message": "OAuth completed successfully",
                "has_refresh_token": bool(tokens.refresh_token),
            }
        else:
            return {
                "status": "error",
                "message": f"Failed to exchange code: {response.status_code}",
                "error": response.text,
            }


def register_oauth_tools(mcp, settings: Settings):
    """Register OAuth tools with the FastMCP server."""
    oauth = OAuthTools(settings)

    @mcp.tool
    async def start_oauth_flow(ctx: Context) -> Dict:
        """
        Start the OAuth authorization flow for Amazon Ads API.

        Returns an authorization URL that the user should visit to grant access.
        The server will automatically handle the callback.
        """
        return await oauth.start_oauth_flow(ctx)

    @mcp.tool
    async def check_oauth_status(ctx: Context) -> Dict:
        """
        Check the current OAuth authentication status.

        Returns whether the user is authenticated and token information.
        """
        return await oauth.check_oauth_status(ctx)

    @mcp.tool
    async def refresh_oauth_token(ctx: Context) -> Dict:
        """
        Manually refresh the OAuth access token.

        This is usually handled automatically, but can be triggered manually if needed.
        """
        return await oauth.refresh_access_token(ctx)

    @mcp.tool
    async def clear_oauth_tokens(ctx: Context) -> Dict:
        """
        Clear all stored OAuth tokens and state.

        Use this to reset authentication or switch to a different account.
        """
        return await oauth.clear_oauth_tokens(ctx)

    return oauth
