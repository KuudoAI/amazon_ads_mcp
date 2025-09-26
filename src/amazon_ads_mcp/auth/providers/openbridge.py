"""OpenBridge authentication provider.

This module implements the OpenBridge authentication provider,
which manages multiple Amazon Ads identities through OpenBridge's
remote identity service.
"""

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import httpx
import jwt
from pydantic import BaseModel, ValidationError

from ...models import AuthCredentials, Identity, Token
from ...utils.http import get_http_client
from ..base import BaseAmazonAdsProvider, BaseIdentityProvider, ProviderConfig
from ..registry import register_provider

logger = logging.getLogger(__name__)


class OpenbridgeTokenResponse(BaseModel):
    """OpenBridge token response model.

    Represents the response from OpenBridge when requesting an
    access token for Amazon Ads API authentication.

    :param data: Raw response data containing token information
    :type data: Dict[str, Any]
    """

    data: Dict[str, Any]

    def get_token(self) -> Optional[str]:
        """Extract token from response.

        Extracts the access token from the OpenBridge response data.

        :return: Access token string if available, None otherwise
        :rtype: Optional[str]
        """
        # The response has data.access_token directly
        return self.data.get("access_token")

    def get_client_id(self) -> Optional[str]:
        """Extract client ID from response.

        Extracts the client ID from the OpenBridge response data.
        Checks multiple possible field names where the client ID might be stored.

        :return: Client ID string if available, None otherwise
        :rtype: Optional[str]
        """
        # Check multiple possible fields for client ID
        # OpenBridge might use different field names
        client_id = (
            self.data.get("client_id")
            or self.data.get("clientId")
            or self.data.get("amazon_advertising_api_client_id")
            or self.data.get("amazonAdvertisingApiClientId")
        )
        return client_id

    def get_scope(self) -> Optional[str]:
        """Extract scope/profile ID from response.

        Extracts the scope (profile ID) from the OpenBridge response data.

        :return: Scope/Profile ID string if available, None otherwise
        :rtype: Optional[str]
        """
        # Check for scope or profile_id in the response
        scope = (
            self.data.get("scope")
            or self.data.get("profile_id")
            or self.data.get("profileId")
            or self.data.get("amazon_advertising_api_scope")
        )
        return scope


@register_provider("openbridge")
class OpenBridgeProvider(BaseAmazonAdsProvider, BaseIdentityProvider):
    """OpenBridge authentication provider.

    Provides authentication and identity management through the OpenBridge
    platform, handling JWT token conversion and remote identity access.
    """

    def __init__(self, config: ProviderConfig):
        """Initialize OpenBridge provider.

        :param config: Provider configuration
        :type config: ProviderConfig
        """
        # Refresh token can come from config OR be provided later via Authorization header
        # Don't require it at initialization time
        self.refresh_token = config.get("refresh_token")

        self._region = config.get("region", "na")

        # OpenBridge API endpoints - configurable via config or env
        self.auth_base_url = config.get("auth_base_url") or os.environ.get(
            "OPENBRIDGE_AUTH_BASE_URL",
            "https://authentication.api.openbridge.io",
        )
        self.identity_base_url = config.get("identity_base_url") or os.environ.get(
            "OPENBRIDGE_IDENTITY_BASE_URL",
            "https://remote-identity.api.openbridge.io",
        )
        self.service_base_url = config.get("service_base_url") or os.environ.get(
            "OPENBRIDGE_SERVICE_BASE_URL", "https://service.api.openbridge.io"
        )

        self._jwt_token: Optional[Token] = None
        self._identities_cache: Dict[tuple, List[Identity]] = {}

    @property
    def provider_type(self) -> str:
        """Return the provider type identifier."""
        return "openbridge"

    @property
    def region(self) -> str:
        """Get the current region."""
        return self._region

    async def initialize(self) -> None:
        """Initialize the provider."""
        logger.info("Initializing OpenBridge provider")
        # Could validate the refresh token here if needed

    async def _get_client(self) -> httpx.AsyncClient:
        """Get shared HTTP client."""
        return await get_http_client()

    def set_refresh_token(self, refresh_token: str) -> None:
        """Set the refresh token dynamically.

        This allows the refresh token to be provided via the Authorization header
        rather than requiring it in the configuration.

        :param refresh_token: The OpenBridge refresh token
        :type refresh_token: str
        """
        self.refresh_token = refresh_token
        # Clear cached JWT when refresh token changes
        self._jwt_token = None

    async def get_token(self) -> Token:
        """Get current JWT token from OpenBridge."""
        if self._jwt_token and await self.validate_token(self._jwt_token):
            return self._jwt_token

        if not self.refresh_token:
            raise ValueError(
                "No refresh token available. Provide it via config or Authorization header."
            )

        return await self._refresh_jwt_token()

    async def _refresh_jwt_token(self) -> Token:
        """Convert refresh token to JWT via OpenBridge."""
        if not self.refresh_token:
            raise ValueError("Cannot refresh JWT: No refresh token available")

        logger.debug("Converting OpenBridge refresh token to JWT")

        client = await self._get_client()

        try:
            response = await client.post(
                f"{self.auth_base_url}/auth/api/ref",
                json={
                    "data": {
                        "type": "APIAuth",
                        "attributes": {"refresh_token": self.refresh_token},
                    }
                },
                headers={"Content-Type": "application/json"},
            )

            if response.status_code not in [200, 202]:
                response.raise_for_status()

            data = response.json()
            token_value = data.get("data", {}).get("attributes", {}).get("token")

            if not token_value:
                raise ValueError("No token in OpenBridge response")

            # Parse the JWT to get expiration
            payload = jwt.decode(token_value, options={"verify_signature": False})
            expires_at_timestamp = payload.get("expires_at", 0)
            expires_at = datetime.fromtimestamp(expires_at_timestamp, tz=timezone.utc)

            self._jwt_token = Token(
                value=token_value,
                expires_at=expires_at,
                token_type="Bearer",
                metadata={
                    "user_id": payload.get("user_id"),
                    "account_id": payload.get("account_id"),
                },
            )

            logger.debug(f"OpenBridge JWT obtained, expires at {expires_at}")
            return self._jwt_token

        except httpx.HTTPError as e:
            logger.error(f"Failed to get OpenBridge JWT: {e}")
            raise
        except Exception as e:
            logger.error(f"Error processing OpenBridge token: {e}")
            raise

    async def validate_token(self, token: Token) -> bool:
        """Validate if token is still valid."""
        buffer = timedelta(minutes=5)
        now = datetime.now(timezone.utc)
        expiry = token.expires_at
        # Ensure both datetimes are timezone-aware for comparison
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        return now < (expiry - buffer)

    async def list_identities(self, **kwargs) -> List[Identity]:
        """List all remote identities from OpenBridge.

        :param kwargs: Optional filters (identity_type, page_size)
        :return: List of identities
        """
        identity_type = kwargs.get("identity_type", "14")  # Default to Amazon Ads
        page_size = kwargs.get("page_size", 100)

        cache_key = (identity_type, page_size)
        if cache_key in self._identities_cache:
            logger.debug(f"Using cached identities for {cache_key}")
            return self._identities_cache[cache_key]

        identities = await self._fetch_identities(identity_type, page_size)

        # Simple cache management
        if len(self._identities_cache) >= 32:
            oldest_key = next(iter(self._identities_cache))
            del self._identities_cache[oldest_key]

        self._identities_cache[cache_key] = identities
        return identities

    async def _fetch_identities(
        self, identity_type: str, page_size: int
    ) -> List[Identity]:
        """Fetch identities from OpenBridge API."""
        logger.info(
            f"Fetching remote identities from OpenBridge (type={identity_type})"
        )

        jwt_token = await self.get_token()
        client = await self._get_client()
        identities = []
        page = 1
        has_more = True

        try:
            while has_more:
                logger.debug(f"Fetching page {page} of identities")
                params = {"page": page, "page_size": page_size}

                if identity_type:
                    params["remote_identity_type"] = identity_type

                response = await client.get(
                    f"{self.identity_base_url}/sri",
                    params=params,
                    headers={
                        "Authorization": f"Bearer {jwt_token.value}",
                        "x-api-key": self.refresh_token,
                    },
                    timeout=httpx.Timeout(30.0, connect=10.0),
                )
                response.raise_for_status()

                data = response.json()
                items = data.get("data", [])
                logger.debug(f"Page {page} has {len(items)} items")

                for item in items:
                    try:
                        identity = Identity(**item)
                        identities.append(identity)
                    except ValidationError as e:
                        logger.warning(f"Failed to parse identity: {e}")
                        continue

                # Check for more pages
                links = data.get("links", {})
                has_more = bool(links.get("next"))

                if not items:
                    logger.debug(f"No items on page {page}, stopping pagination")
                    has_more = False

                page += 1

                if page > 100:
                    logger.warning("Reached maximum page limit (100)")
                    break

            logger.info(f"Found {len(identities)} remote identities")
            return identities

        except httpx.HTTPError as e:
            logger.error(f"Failed to list identities: {e}")
            raise

    async def get_identity(self, identity_id: str) -> Optional[Identity]:
        """Get specific identity by ID."""
        identities = await self.list_identities()
        for identity in identities:
            if identity.id == identity_id:
                return identity
        return None

    async def get_identity_credentials(self, identity_id: str) -> AuthCredentials:
        """Get Amazon Ads credentials for specific identity."""
        logger.info(f"Getting credentials for identity {identity_id}")

        identity = await self.get_identity(identity_id)
        if not identity:
            raise ValueError(f"Identity {identity_id} not found")

        jwt_token = await self.get_token()
        client = await self._get_client()

        try:
            response = await client.get(
                f"{self.service_base_url}/service/amzadv/token/{identity_id}",
                headers={
                    "Authorization": f"Bearer {jwt_token.value}",
                    "x-api-key": self.refresh_token,
                },
            )
            response.raise_for_status()

            data = response.json()
            # Log sanitized response metadata (without sensitive tokens)
            logger.debug(
                "OpenBridge token response received",
                extra={
                    "has_data": "data" in data,
                    "data_keys": list(data.get("data", {}).keys()) if "data" in data else [],
                }
            )

            token_data = OpenbridgeTokenResponse(data=data.get("data", {}))
            amazon_ads_token = token_data.get_token()
            client_id = token_data.get_client_id()
            scope = token_data.get_scope()

            # Log what we extracted
            logger.info(
                f"Extracted from OpenBridge response - token: {bool(amazon_ads_token)}, client_id: {client_id}, scope: {scope}"
            )

            if not amazon_ads_token:
                raise ValueError("No Amazon Ads token in response")

            # Handle client ID fallback
            if not client_id:
                # Only fall back to env var if OpenBridge didn't provide a client ID
                env_client_id = os.getenv("AMAZON_AD_API_CLIENT_ID")
                if env_client_id:
                    logger.info(
                        "OpenBridge didn't provide client ID, using AMAZON_AD_API_CLIENT_ID env var"
                    )
                    client_id = env_client_id
                else:
                    raise ValueError(
                        "No client ID from OpenBridge and AMAZON_AD_API_CLIENT_ID not set"
                    )
            elif client_id.lower() == "openbridge":
                # Legacy: Some older OpenBridge setups might return "openbridge" as placeholder
                logger.warning(
                    "OpenBridge returned 'openbridge' as client ID placeholder. "
                    "Please update your OpenBridge configuration to provide the real client ID."
                )
                env_client_id = os.getenv("AMAZON_AD_API_CLIENT_ID")
                if env_client_id:
                    logger.info("Using AMAZON_AD_API_CLIENT_ID env var as fallback")
                    client_id = env_client_id
                else:
                    raise ValueError(
                        "OpenBridge returned 'openbridge' placeholder and AMAZON_AD_API_CLIENT_ID not set"
                    )

            expires_at = datetime.now(timezone.utc) + timedelta(hours=1)

            # Get the identity's region for the correct endpoint
            identity_region = identity.attributes.get("region", "na").lower()
            logger.info(f"Using identity region: {identity_region}")

            # Build headers with all available information
            headers = {
                "Authorization": f"Bearer {amazon_ads_token}",
                "Amazon-Advertising-API-ClientId": client_id,
            }

            # Add scope if provided by OpenBridge
            if scope:
                headers["Amazon-Advertising-API-Scope"] = scope
                logger.info(f"Using scope from OpenBridge: {scope}")

            return AuthCredentials(
                identity_id=identity_id,
                access_token=amazon_ads_token,
                expires_at=expires_at,
                base_url=self.get_region_endpoint(identity_region),
                headers=headers,
            )

        except httpx.HTTPError as e:
            logger.error(f"Failed to get identity credentials: {e}")
            raise

    async def get_headers(self) -> Dict[str, str]:
        """Get authentication headers.

        For OpenBridge, this returns empty headers since all headers
        come from the identity-specific credentials.
        """
        # OpenBridge headers are identity-specific and come from
        # get_identity_credentials(). Return empty here to avoid
        # overriding with incorrect values.
        return {}

    def requires_identity_region_routing(self) -> bool:
        """Check if requests must be routed to identity's region.

        OpenBridge always routes requests to the region associated
        with the active identity.

        :return: True - OpenBridge requires identity-based routing
        :rtype: bool
        """
        return True

    def headers_are_identity_specific(self) -> bool:
        """Check if auth headers vary per identity.

        OpenBridge uses different credentials for each identity,
        so headers cannot be reconstructed from just a cached token.

        :return: True - OpenBridge headers are identity-specific
        :rtype: bool
        """
        return True

    def region_controlled_by_identity(self) -> bool:
        """Check if region is determined by active identity.

        In OpenBridge, the region cannot be changed independently;
        it's determined by the active identity's region.

        :return: True - OpenBridge region is controlled by identity
        :rtype: bool
        """
        return True

    async def close(self) -> None:
        """Clean up provider resources."""
        self._identities_cache.clear()
        self._jwt_token = None
