"""Direct Amazon Ads API authentication provider.

This module implements direct authentication using Amazon Ads API credentials,
if you are using your own Amazon Ads API credentials/app.
"""

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

import httpx

from ...models import AuthCredentials, Identity, Token
from ...utils.http import get_http_client
from ..base import BaseAmazonAdsProvider, BaseIdentityProvider, ProviderConfig
from ..registry import register_provider

logger = logging.getLogger(__name__)


@register_provider("direct")
class DirectAmazonAdsProvider(BaseAmazonAdsProvider, BaseIdentityProvider):
    """Direct Amazon Ads API authentication provider.

    Provides authentication using Amazon Ads API credentials directly,
    implementing the "Bring Your Own API" (BYOA) pathway.
    """

    def __init__(self, config: ProviderConfig):
        """Initialize direct Amazon Ads provider.

        :param config: Provider configuration with client_id, client_secret, refresh_token
        :type config: ProviderConfig
        """
        self.client_id = config.get("client_id")
        self.client_secret = config.get("client_secret")
        self.refresh_token = config.get("refresh_token")

        # Allow missing refresh_token for OAuth flow bootstrapping
        if not self.client_id or not self.client_secret:
            raise ValueError(
                "Direct provider requires 'client_id' and 'client_secret' in config"
            )

        if not self.refresh_token:
            logger.warning(
                "No refresh_token configured. Use OAuth tools to obtain one: "
                "start_oauth_flow -> visit URL -> check_oauth_status"
            )

        self.profile_id = config.get("profile_id")
        self._region = config.get("region", "na")
        self._access_token: Optional[Token] = None
        # Serializes concurrent refresh token -> access token exchanges
        # so that N in-flight tool calls do not trigger N OAuth2 requests.
        self._refresh_lock: Optional[asyncio.Lock] = None

    @property
    def provider_type(self) -> str:
        """
        Return the provider type identifier.

        :return: Provider type identifier 'direct'
        :rtype: str
        """
        return "direct"

    @property
    def region(self) -> str:
        """
        Get the current region.

        :return: Region code (na, eu, or fe)
        :rtype: str
        """
        return self._region

    async def initialize(self) -> None:
        """
        Initialize the provider.

        Performs any asynchronous initialization required for the direct
        authentication provider.

        :return: None
        :rtype: None
        """
        logger.info(
            f"Initializing Direct Amazon Ads provider for region {self._region}"
        )

    async def _get_client(self) -> httpx.AsyncClient:
        """
        Get shared HTTP client.

        Retrieves the shared HTTP client instance for making API requests.

        :return: Shared HTTP client instance
        :rtype: httpx.AsyncClient
        """
        return await get_http_client()

    async def get_token(self) -> Token:
        """
        Get current access token from Amazon Ads API.

        Retrieves the current access token, first attempting to retrieve
        from cache, then refreshing if necessary.

        :return: Valid access token
        :rtype: Token
        :raises ValueError: If no refresh token is available
        """
        # Try to get from AuthManager's token store first
        auth_manager = None
        try:
            from ..manager import get_auth_manager

            auth_manager = get_auth_manager()

            if auth_manager and hasattr(auth_manager, "get_token"):
                from ..token_store import TokenKind

                token_entry = await auth_manager.get_token(
                    provider_type="direct",
                    identity_id="direct-auth",
                    token_kind=TokenKind.ACCESS,
                    region=self._region,
                )

                if token_entry and not token_entry.is_expired():
                    self._access_token = Token(
                        value=token_entry.value,
                        expires_at=token_entry.expires_at,
                        token_type="Bearer",
                        metadata=token_entry.metadata,
                    )
                    logger.debug("Retrieved access token from unified token store")
                    return self._access_token
        except Exception as e:
            logger.debug(f"Could not get token from store: {e}")

        # Check local cache
        if self._access_token and await self.validate_token(self._access_token):
            return self._access_token

        return await self._refresh_access_token()

    async def _refresh_access_token(self) -> Token:
        """
        Exchange refresh token for access token via Amazon OAuth2.

        Performs OAuth2 token refresh to obtain a new access token
        from Amazon's authentication servers.

        Concurrent callers are coalesced via an ``asyncio.Lock`` so only
        one OAuth2 exchange runs at a time; waiters re-use the cached
        token set by the first winner.

        :return: New access token with expiration
        :rtype: Token
        :raises ValueError: If no refresh token is available or token response is invalid
        :raises httpx.HTTPError: If the OAuth2 token request fails
        """
        if self._refresh_lock is None:
            self._refresh_lock = asyncio.Lock()
        async with self._refresh_lock:
            # Inside the lock, see if another task already refreshed.
            if self._access_token and await self.validate_token(self._access_token):
                return self._access_token
            return await self._refresh_access_token_locked()

    async def _refresh_access_token_locked(self) -> Token:
        # Check if refresh token is available from secure store
        if not self.refresh_token:
            try:
                from ..secure_token_store import get_secure_token_store

                secure_store = get_secure_token_store()
                token_entry = secure_store.get_token("oauth_refresh_token")
                if token_entry and token_entry.get("value"):
                    self.refresh_token = token_entry["value"]
                    logger.info("Found refresh token in secure store")
                else:
                    raise ValueError(
                        "No refresh token available. Use OAuth tools to obtain one: "
                        "start_oauth_flow -> visit URL -> check_oauth_status"
                    )
            except ImportError:
                logger.warning("Secure token store not available")
                raise ValueError(
                    "No refresh token available. Use OAuth tools to obtain one: "
                    "start_oauth_flow -> visit URL -> check_oauth_status"
                )
            except Exception as e:
                logger.error(f"Error accessing secure token store: {e}")
                raise ValueError(
                    "No refresh token available. Use OAuth tools to obtain one: "
                    "start_oauth_flow -> visit URL -> check_oauth_status"
                )

        logger.debug("Exchanging refresh token for Amazon Ads access token")

        client = await self._get_client()
        auth_endpoint = self.get_oauth_endpoint()

        try:
            response = await client.post(
                auth_endpoint,
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": self.refresh_token,
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

            if response.status_code != 200:
                logger.error(
                    f"Token refresh failed: {response.status_code} - {response.text}"
                )
                response.raise_for_status()

            data = response.json()
            access_token = data.get("access_token")
            expires_in = data.get("expires_in", 3600)

            if not access_token:
                raise ValueError("No access token in Amazon response")

            expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)

            self._access_token = Token(
                value=access_token,
                expires_at=expires_at,
                token_type="Bearer",
                metadata={
                    "client_id": self.client_id,
                    "region": self._region,
                },
            )

            # Store in unified token store
            try:
                from ..manager import get_auth_manager

                auth_manager = get_auth_manager()

                if auth_manager and hasattr(auth_manager, "set_token"):
                    from ..token_store import TokenKind

                    await auth_manager.set_token(
                        provider_type="direct",
                        identity_id="direct-auth",
                        token_kind=TokenKind.ACCESS,
                        token=access_token,
                        expires_at=expires_at,
                        metadata={
                            "client_id": self.client_id,
                            "region": self._region,
                            "token_type": "Bearer",
                        },
                        region=self._region,
                    )
                    logger.debug("Stored access token in unified token store")
            except Exception as e:
                logger.debug(f"Could not store token: {e}")

            logger.debug(f"Amazon Ads access token obtained, expires at {expires_at}")
            return self._access_token

        except httpx.HTTPError as e:
            logger.error(f"Failed to refresh Amazon Ads token: {e}")
            raise
        except Exception as e:
            logger.error(f"Error processing Amazon token response: {e}")
            raise

    async def validate_token(self, token: Token) -> bool:
        """
        Validate if token is still valid.

        Checks if the provided token is still valid, considering a 5-minute
        buffer before expiration to ensure safe usage.

        :param token: Token to validate
        :type token: Token
        :return: True if token is valid, False otherwise
        :rtype: bool
        """
        buffer = timedelta(minutes=5)
        now = datetime.now(timezone.utc)
        expiry = token.expires_at
        # Ensure both datetimes are timezone-aware for comparison
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        return now < (expiry - buffer)

    async def list_identities(self, **kwargs) -> List[Identity]:
        """
        List identities for direct auth.

        For direct auth, creates a single synthetic identity
        representing the authenticated account.

        :param kwargs: Unused filter parameters
        :type kwargs: Any
        :return: List containing the single direct auth identity
        :rtype: List[Identity]
        """
        identity = Identity(
            id="direct-auth",
            type="amazon_ads_direct",
            attributes={
                "name": "Direct Amazon Ads Account",
                "client_id": self.client_id,
                "region": self._region,
                "profile_id": self.profile_id,
                "auth_method": "direct",
            },
        )
        return [identity]

    async def get_identity(self, identity_id: str) -> Optional[Identity]:
        """
        Get specific identity by ID.

        Retrieves the direct auth identity if the ID matches.

        :param identity_id: Identity ID to retrieve
        :type identity_id: str
        :return: Identity if ID matches 'direct-auth', None otherwise
        :rtype: Optional[Identity]
        """
        if identity_id == "direct-auth":
            identities = await self.list_identities()
            return identities[0]
        return None

    async def get_identity_credentials(self, identity_id: str) -> AuthCredentials:
        """
        Get Amazon Ads credentials for the direct auth identity.

        Retrieves authentication credentials including access token and
        required headers for API requests.

        :param identity_id: Identity ID (must be 'direct-auth')
        :type identity_id: str
        :return: Authentication credentials for Amazon Ads API
        :rtype: AuthCredentials
        :raises ValueError: If identity_id is not 'direct-auth'
        """
        if identity_id != "direct-auth":
            raise ValueError(f"Unknown identity: {identity_id}")

        logger.info("Getting credentials for direct Amazon Ads auth")

        token = await self.get_token()
        headers = await self.get_headers()

        return AuthCredentials(
            identity_id=identity_id,
            access_token=token.value,
            expires_at=token.expires_at,
            base_url=self.get_region_endpoint(),
            headers=headers,
        )

    async def get_headers(self) -> Dict[str, str]:
        """
        Get authentication headers for API requests.

        Generates the required headers for Amazon Ads API requests,
        including Authorization and ClientId headers.

        :return: Dictionary of authentication headers
        :rtype: Dict[str, str]
        """
        # If no refresh token, return minimal headers for OAuth flow
        if not self.refresh_token:
            return {
                "Amazon-Advertising-API-ClientId": self.client_id,
                # No Authorization header without token
            }

        token = await self.get_token()

        headers = {
            "Authorization": f"Bearer {token.value}",
            "Amazon-Advertising-API-ClientId": self.client_id,
        }

        # Add profile ID if configured
        if self.profile_id:
            headers["Amazon-Advertising-API-Scope"] = self.profile_id

        return headers

    async def close(self) -> None:
        """
        Clean up provider resources.

        Clears cached tokens and releases any held resources.

        :return: None
        :rtype: None
        """
        self._access_token = None
