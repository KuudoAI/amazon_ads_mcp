"""OpenBridge authentication provider.

This module implements the OpenBridge authentication provider,
which manages multiple Amazon Ads identities through OpenBridge's
remote identity service.
"""

import asyncio
import hashlib
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
from ..session_state import get_refresh_token_override

logger = logging.getLogger(__name__)

CLIENT_ID_CANDIDATE_KEYS = (
    "oauth_client_id",
    "client_id",
    "clientId",
    "amazon_advertising_api_client_id",
    "amazonAdvertisingApiClientId",
)


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

        # JWT cache keyed by token fingerprint (prevents cross-client leakage)
        self._jwt_tokens: Dict[str, Token] = {}
        # Identity cache keyed by (identity_type, page_size, token_fingerprint)
        self._identities_cache: Dict[tuple, List[Identity]] = {}
        # Max cache entries to prevent unbounded growth
        self._max_cache_entries = 32
        # Per-fingerprint locks that serialize concurrent refresh-token ->
        # JWT exchanges so bursty tool calls share a single network fetch.
        self._refresh_locks: Dict[str, asyncio.Lock] = {}
        self._refresh_locks_guard: Optional[asyncio.Lock] = None

    async def _get_refresh_lock(self, fingerprint: str) -> asyncio.Lock:
        if self._refresh_locks_guard is None:
            self._refresh_locks_guard = asyncio.Lock()
        async with self._refresh_locks_guard:
            lock = self._refresh_locks.get(fingerprint)
            if lock is None:
                lock = asyncio.Lock()
                self._refresh_locks[fingerprint] = lock
            return lock

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
        """Set the per-request refresh token via ContextVar.

        .. deprecated::
            Middleware now sets the ContextVar directly via
            ``set_refresh_token_override()``. This method exists only for
            backward compatibility with callers outside the middleware chain.
            It does **not** mutate ``self.refresh_token`` (the singleton
            default) to prevent cross-client leakage.

        :param refresh_token: The OpenBridge refresh token
        :type refresh_token: str
        """
        from ..session_state import set_refresh_token_override

        set_refresh_token_override(refresh_token)

    def _get_effective_refresh_token(self) -> Optional[str]:
        """Return the refresh token for the current request context.

        Priority: per-request ContextVar override → env-configured default.
        """
        return get_refresh_token_override() or self.refresh_token

    def _token_fingerprint(self, token: Optional[str] = None) -> str:
        """SHA-256 fingerprint of the effective refresh token.

        Used as cache key discriminator to prevent cross-client cache hits.

        :param token: Token to fingerprint. Uses effective token if None.
        :type token: Optional[str]
        :return: Hex digest of SHA-256 hash
        :rtype: str
        """
        effective = token or self._get_effective_refresh_token() or ""
        return hashlib.sha256(effective.encode()).hexdigest()

    async def get_token(self) -> Token:
        """Get current JWT token from OpenBridge."""
        fingerprint = self._token_fingerprint()
        cached = self._jwt_tokens.get(fingerprint)
        if cached and await self.validate_token(cached):
            return cached

        effective_token = self._get_effective_refresh_token()
        if not effective_token:
            raise ValueError(
                "No OpenBridge token available. Set OPENBRIDGE_REFRESH_TOKEN env var, "
                "or pass via X-Openbridge-Token header (preferred) or Authorization: Bearer header."
            )

        return await self._refresh_jwt_token()

    async def _refresh_jwt_token(self) -> Token:
        """Convert refresh token to JWT via OpenBridge.

        Concurrent callers for the same refresh token share a single
        network fetch via a per-fingerprint ``asyncio.Lock``; waiters
        return the freshly cached JWT.
        """
        effective_token = self._get_effective_refresh_token()
        if not effective_token:
            raise ValueError("Cannot refresh JWT: No refresh token available")

        fingerprint = self._token_fingerprint(effective_token)
        lock = await self._get_refresh_lock(fingerprint)
        async with lock:
            cached = self._jwt_tokens.get(fingerprint)
            if cached and await self.validate_token(cached):
                return cached
            return await self._refresh_jwt_token_locked(effective_token, fingerprint)

    async def _refresh_jwt_token_locked(
        self, effective_token: str, fingerprint: str
    ) -> Token:
        logger.debug("Converting OpenBridge refresh token to JWT")

        client = await self._get_client()

        try:
            response = await client.post(
                f"{self.auth_base_url}/auth/api/ref",
                json={
                    "data": {
                        "type": "APIAuth",
                        "attributes": {"refresh_token": effective_token},
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

            jwt_token = Token(
                value=token_value,
                expires_at=expires_at,
                token_type="Bearer",
                metadata={
                    "user_id": payload.get("user_id"),
                    "account_id": payload.get("account_id"),
                },
            )

            if len(self._jwt_tokens) >= self._max_cache_entries:
                oldest_key = next(iter(self._jwt_tokens))
                del self._jwt_tokens[oldest_key]
            self._jwt_tokens[fingerprint] = jwt_token

            logger.debug(f"OpenBridge JWT obtained, expires at {expires_at}")
            return jwt_token

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

        # Include token fingerprint in cache key for per-client isolation
        fingerprint = self._token_fingerprint()
        cache_key = (identity_type, page_size, fingerprint)
        if cache_key in self._identities_cache:
            logger.debug(f"Using cached identities for type={identity_type}")
            return self._identities_cache[cache_key]

        identities = await self._fetch_identities(identity_type, page_size)

        # Simple cache management with bounded eviction
        if len(self._identities_cache) >= self._max_cache_entries:
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
                        "x-api-key": self._get_effective_refresh_token(),
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

    @staticmethod
    def _normalize_client_id(value: Optional[str]) -> Optional[str]:
        """Normalize and reject unusable client-id placeholders."""
        if not value:
            return None
        normalized = str(value).strip()
        if not normalized:
            return None
        if normalized.lower() == "openbridge":
            return None
        return normalized

    @classmethod
    def _extract_client_id_from_obj(cls, payload: Any) -> Optional[str]:
        """Find a usable client ID recursively in nested payloads."""
        if isinstance(payload, dict):
            for key in CLIENT_ID_CANDIDATE_KEYS:
                resolved = cls._normalize_client_id(payload.get(key))
                if resolved:
                    return resolved
            for value in payload.values():
                resolved = cls._extract_client_id_from_obj(value)
                if resolved:
                    return resolved
            return None

        if isinstance(payload, list):
            for item in payload:
                resolved = cls._extract_client_id_from_obj(item)
                if resolved:
                    return resolved
        return None

    @staticmethod
    def _extract_remote_identity_type_application_ids(identity: Identity) -> List[str]:
        """Extract related remote-identity-type-application IDs from identity."""
        relationships = getattr(identity, "relationships", None)
        if not isinstance(relationships, dict):
            return []

        rel = relationships.get("remote_identity_type_application")
        if not isinstance(rel, dict):
            return []

        data = rel.get("data")
        ids: List[str] = []
        if isinstance(data, dict):
            app_id = data.get("id")
            if app_id:
                ids.append(str(app_id))
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and item.get("id"):
                    ids.append(str(item["id"]))
        return ids

    async def _try_fetch_json(
        self,
        client: httpx.AsyncClient,
        url: str,
        headers: Dict[str, str],
        params: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Best-effort JSON fetch used by client-id fallback resolution."""
        try:
            response = await client.get(
                url,
                headers=headers,
                params=params,
                timeout=httpx.Timeout(20.0, connect=10.0),
            )
            if response.status_code >= 400:
                logger.debug(
                    "Client-id fallback probe failed: GET %s -> %s",
                    url,
                    response.status_code,
                )
                return None
            payload = response.json()
            if isinstance(payload, dict):
                return payload
        except Exception as exc:
            logger.debug("Client-id fallback probe failed for %s: %s", url, exc)
        return None

    async def _resolve_client_id_from_identity_relationship(
        self,
        identity: Identity,
        client: httpx.AsyncClient,
        jwt_token: Token,
    ) -> Optional[str]:
        """Resolve client ID from identity payload/relationships when token API omits it."""
        resolved = self._extract_client_id_from_obj(
            {
                "attributes": getattr(identity, "attributes", {}) or {},
                "relationships": getattr(identity, "relationships", {}) or {},
            }
        )
        if resolved:
            return resolved

        headers = {
            "Authorization": f"Bearer {jwt_token.value}",
            "x-api-key": self._get_effective_refresh_token(),
        }

        # First try richer identity fetch, with and without relationship include.
        identity_urls = [
            (f"{self.identity_base_url}/sri/{identity.id}", {"include": "remote_identity_type_application"}),
            (f"{self.identity_base_url}/sri/{identity.id}", None),
        ]
        for url, params in identity_urls:
            payload = await self._try_fetch_json(client, url, headers, params=params)
            if not payload:
                continue
            resolved = self._extract_client_id_from_obj(payload)
            if resolved:
                return resolved

        # Then follow relationship IDs through likely application endpoints.
        application_ids = self._extract_remote_identity_type_application_ids(identity)
        for application_id in application_ids:
            candidate_urls = [
                f"{self.identity_base_url}/rita/{application_id}",
                f"{self.identity_base_url}/remote-identity-type-applications/{application_id}",
                f"{self.identity_base_url}/remote_identity_type_applications/{application_id}",
            ]
            for url in candidate_urls:
                payload = await self._try_fetch_json(client, url, headers)
                if not payload:
                    continue
                resolved = self._extract_client_id_from_obj(payload)
                if resolved:
                    return resolved

        return None

    async def get_identity_credentials(self, identity_id: str) -> AuthCredentials:
        """Get Amazon Ads credentials for specific identity.

        OpenBridge handles token refresh internally - each call to their
        /service/amzadv/token/<id> endpoint returns a fresh, valid token.
        We parse the expiration if possible to enable client-side caching.
        """
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
                    "x-api-key": self._get_effective_refresh_token(),
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

            normalized_client_id = self._normalize_client_id(client_id)

            # Handle client ID fallback
            if not normalized_client_id:
                relationship_client_id = (
                    await self._resolve_client_id_from_identity_relationship(
                        identity=identity,
                        client=client,
                        jwt_token=jwt_token,
                    )
                )
                if relationship_client_id:
                    logger.info(
                        "Resolved client ID from identity relationship/application metadata"
                    )
                    normalized_client_id = relationship_client_id

            if not normalized_client_id:
                # Only fall back to env var if OpenBridge didn't provide a client ID
                env_client_id = os.getenv("AMAZON_AD_API_CLIENT_ID")
                if env_client_id:
                    logger.info(
                        "OpenBridge didn't provide client ID, using AMAZON_AD_API_CLIENT_ID env var"
                    )
                    normalized_client_id = env_client_id
                else:
                    raise ValueError(
                        "No client ID from OpenBridge and AMAZON_AD_API_CLIENT_ID not set"
                    )

            # Try to parse expiration from the Amazon token if it's a JWT
            expires_at = None
            try:
                # Amazon tokens are usually JWTs we can decode
                payload = jwt.decode(amazon_ads_token, options={"verify_signature": False})
                # Check for standard JWT expiration claim
                if "exp" in payload:
                    expires_at = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
                    logger.info(f"Parsed Amazon token expiration: {expires_at}")
                elif "expires_at" in payload:
                    expires_at = datetime.fromtimestamp(payload["expires_at"], tz=timezone.utc)
                    logger.info(f"Parsed Amazon token expiration: {expires_at}")
            except Exception as e:
                logger.debug(f"Could not parse Amazon token as JWT: {e}")

            # If we couldn't parse expiration, use a conservative default
            # OpenBridge should always return fresh tokens, but we use a short
            # expiration to ensure frequent refresh checks
            if expires_at is None:
                expires_at = datetime.now(timezone.utc) + timedelta(minutes=55)
                logger.info("Using default 55-minute expiration for Amazon token")
            else:
                # Check if the token is already expired or about to expire
                now = datetime.now(timezone.utc)
                time_until_expiry = expires_at - now
                if time_until_expiry.total_seconds() < 300:  # Less than 5 minutes
                    logger.warning(
                        f"OpenBridge returned token expiring in {time_until_expiry.total_seconds():.0f} seconds!"
                    )
                    # OpenBridge should not return expired tokens, but log if it happens
                    if time_until_expiry.total_seconds() < 0:
                        logger.error("OpenBridge returned an EXPIRED token! This should not happen.")

            # Get the identity's region for the correct endpoint
            identity_region = identity.attributes.get("region", "na").lower()
            logger.info(f"Using identity region: {identity_region}")

            # Build headers with all available information
            headers = {
                "Authorization": f"Bearer {amazon_ads_token}",
                "Amazon-Advertising-API-ClientId": normalized_client_id,
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
        self._jwt_tokens.clear()
