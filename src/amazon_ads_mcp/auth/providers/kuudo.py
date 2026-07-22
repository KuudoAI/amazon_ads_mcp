"""Kuudo auth provider for the Amazon Ads MCP server.

Runtime configuration:
- KUUDO_API_BASE_URL: Kuudo Next app origin. The development environment is
  ``https://amazon-spapi-dev.kuudo.ai/``.
- KUUDO_API_KEY: Kuudo sk_* M2M API key with amazon-connections:read and
  amazon-tokens:vend scopes.

Request flow:
1. POST {KUUDO_API_BASE_URL}/api/auth/token-exchange
   Header: Authorization: Bearer <KUUDO_API_KEY>
   Returns a short-lived Kuudo platform JWT.
2. GET {KUUDO_API_BASE_URL}/api/mcp/amazon/identities
   Header: Authorization: Bearer <platform-jwt>
   Optional query: provider=amazon_ads or provider=amazon_sp_api.
   Returns metadata-only identities keyed by Kuudo amazon_connections.id.
3. POST {KUUDO_API_BASE_URL}/api/mcp/amazon/identities/{id}/token
   Header: Authorization: Bearer <platform-jwt>
   Optional body: {"provider": "amazon_ads", "profile_id": "123456789"}.
   Returns a short-lived Amazon access token plus product metadata.

This is not a FastMCP server `RemoteAuthProvider` like ScalekitProvider.
It is an Openbridge-style downstream credential provider for MCP tools that
need Kuudo-managed Amazon credentials.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import secrets
from collections import OrderedDict
from contextvars import ContextVar, Token as ContextToken
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote

import httpx

from ...models import AuthCredentials, Identity, Token
from ..base import BaseAmazonAdsProvider, BaseIdentityProvider, ProviderConfig
from ..registry import register_provider

__all__ = [
    "AuthCredentials",
    "Identity",
    "KuudoAuthError",
    "KuudoAmazonAdsProvider",
    "KuudoConfigError",
    "KuudoHTTPError",
    "KuudoProviderConfig",
    "Token",
]

AMAZON_ADS_ENDPOINTS = {
    "na": "https://advertising-api.amazon.com",
    "eu": "https://advertising-api-eu.amazon.com",
    "fe": "https://advertising-api-fe.amazon.com",
}

AMAZON_SP_API_ENDPOINTS = {
    "na": "https://sellingpartnerapi-na.amazon.com",
    "eu": "https://sellingpartnerapi-eu.amazon.com",
    "fe": "https://sellingpartnerapi-fe.amazon.com",
}


class KuudoAuthError(RuntimeError):
    """Base error for Kuudo auth provider failures."""


class KuudoConfigError(KuudoAuthError):
    """Raised when required provider configuration is missing."""


class KuudoHTTPError(KuudoAuthError):
    """Raised when Kuudo returns an unsuccessful response."""


@dataclass
class KuudoProviderConfig:
    """Normalized configuration for the Kuudo provider."""

    base_url: str | None = None
    api_key: str | None = None
    provider: str | None = None
    region: str = "na"
    timeout_seconds: float = 30.0
    token_exchange_path: str = "/api/auth/token-exchange"
    identities_path: str = "/api/mcp/amazon/identities"
    identity_token_path: str = "/api/mcp/amazon/identities/{identity_id}/token"
    cache_buffer_seconds: int = 300
    identity_cache_ttl_seconds: int = 300
    max_cache_entries: int = 128
    http_client: httpx.AsyncClient | None = None


@register_provider("kuudo")
class KuudoAmazonAdsProvider(BaseAmazonAdsProvider, BaseIdentityProvider):
    """Provide Kuudo-managed Amazon Ads identities and credentials.

    The provider mirrors the Openbridge-style three-stage flow:

    1. exchange a long-lived Kuudo API key for a short-lived platform JWT,
    2. list organization-scoped Amazon authorization identities,
    3. vend an identity-scoped Amazon access token.
    """

    def __init__(
        self,
        config: KuudoProviderConfig | ProviderConfig | Any | None = None,
        *,
        base_url: str | None = None,
        api_key: str | None = None,
        provider: str | None = None,
        region: str | None = None,
        timeout_seconds: float | None = None,
        token_exchange_path: str | None = None,
        identities_path: str | None = None,
        identity_token_path: str | None = None,
        cache_buffer_seconds: int | None = None,
        identity_cache_ttl_seconds: int | None = None,
        max_cache_entries: int | None = None,
        http_client: httpx.AsyncClient | None = None,
        **kwargs: Any,
    ):
        explicit_config = {
            "base_url": base_url,
            "api_key": api_key,
            "provider": provider,
            "region": region,
            "timeout_seconds": timeout_seconds,
            "token_exchange_path": token_exchange_path,
            "identities_path": identities_path,
            "identity_token_path": identity_token_path,
            "cache_buffer_seconds": cache_buffer_seconds,
            "identity_cache_ttl_seconds": identity_cache_ttl_seconds,
            "max_cache_entries": max_cache_entries,
            "http_client": http_client,
        }
        explicit_config.update(kwargs)
        self.config = self._coerce_config(
            config,
            {key: value for key, value in explicit_config.items() if value is not None},
        )
        self._current_api_key: ContextVar[str | None] = ContextVar(
            "kuudo_current_api_key",
            default=None,
        )
        self._current_api_key_fingerprint: ContextVar[str | None] = ContextVar(
            "kuudo_current_api_key_fingerprint",
            default=None,
        )
        self._client: httpx.AsyncClient | None = self.config.http_client
        self._owns_client = self.config.http_client is None
        self._fingerprint_salt = secrets.token_bytes(32)
        self._configured_api_key_fingerprint: str | None = None
        self._configured_api_key_fingerprint_lock = asyncio.Lock()
        self._tokens: OrderedDict[str, Token] = OrderedDict()
        self._identities: OrderedDict[
            tuple[str, str | None, tuple[tuple[str, str], ...]],
            tuple[datetime, list[Identity]],
        ] = OrderedDict()
        self._credentials: OrderedDict[
            tuple[str, str, str | None, str | None],
            AuthCredentials,
        ] = OrderedDict()

    @property
    def provider_type(self) -> str:
        return "kuudo"

    @property
    def region(self) -> str:
        return self.config.region

    async def initialize(self) -> None:
        self._require_base_url()
        if self.config.api_key:
            await self._fingerprint_for(self.config.api_key)
        await self._get_client()

    async def get_token(self, api_key: str | None = None) -> Token:
        effective_api_key = self._get_effective_api_key(api_key)
        fingerprint = await self._fingerprint_for(effective_api_key)
        return await self._get_token(effective_api_key, fingerprint)

    async def _get_token(self, effective_api_key: str, fingerprint: str) -> Token:
        cached = self._tokens.get(fingerprint)
        if cached and await self.validate_token(cached):
            return cached

        client = await self._get_client()
        response = await client.post(
            self._url(self.config.token_exchange_path),
            headers={"Authorization": f"Bearer {effective_api_key}"},
        )
        self._raise_for_status(response, "token exchange")
        payload = response.json()

        token_value = self._first_string(
            payload,
            "access_token",
            "token",
            ("data", "attributes", "token"),
        )
        if not token_value:
            raise KuudoAuthError("Kuudo token exchange did not return an access token")

        token = Token(
            value=token_value,
            token_type=self._first_string(payload, "token_type") or "Bearer",
            expires_at=self._extract_expiration(payload, token_value),
            scope=self._first_string(payload, "scope"),
            metadata={
                "organization_id": self._first_string(payload, "organization_id"),
                "client_id": self._first_string(payload, "client_id"),
            },
        )
        self._remember(self._tokens, fingerprint, token)
        return token

    async def validate_token(self, token: Token) -> bool:
        expires_at = self._aware(token.expires_at)
        return datetime.now(timezone.utc) < (
            expires_at - timedelta(seconds=self.config.cache_buffer_seconds)
        )

    async def list_identities(
        self,
        *,
        provider: str | None = None,
        api_key: str | None = None,
        force_refresh: bool = False,
        **params: Any,
    ) -> list[Identity]:
        params.pop("identity_type", None)
        effective_api_key = self._get_effective_api_key(api_key)
        fingerprint = await self._fingerprint_for(effective_api_key)
        provider_filter = provider or self.config.provider
        query_params = {key: value for key, value in params.items() if value is not None}
        cache_key = (fingerprint, provider_filter, self._cacheable_params(query_params))
        cached = self._identities.get(cache_key)
        if cached and not force_refresh:
            cached_at, identities = cached
            if datetime.now(timezone.utc) < (
                cached_at + timedelta(seconds=self.config.identity_cache_ttl_seconds)
            ):
                return identities

        token = await self._get_token(effective_api_key, fingerprint)
        if provider_filter:
            query_params["provider"] = provider_filter

        client = await self._get_client()
        response = await client.get(
            self._url(self.config.identities_path),
            headers={"Authorization": f"Bearer {token.value}"},
            params=query_params or None,
        )
        self._raise_for_status(response, "identity list")
        identities = [
            self._parse_identity(item) for item in self._extract_items(response.json())
        ]
        self._remember(
            self._identities,
            cache_key,
            (datetime.now(timezone.utc), identities),
        )
        return identities

    async def get_identity(
        self,
        identity_id: str,
        *,
        api_key: str | None = None,
        provider: str | None = None,
    ) -> Identity | None:
        identities = await self.list_identities(api_key=api_key, provider=provider)
        return next((identity for identity in identities if identity.id == identity_id), None)

    async def get_identity_credentials(
        self,
        identity_id: str,
        *,
        api_key: str | None = None,
        provider: str | None = None,
        profile_id: str | int | None = None,
        force_refresh: bool = False,
    ) -> AuthCredentials:
        if not identity_id or not identity_id.strip():
            raise KuudoAuthError("Kuudo identity_id must be nonempty")

        effective_api_key = self._get_effective_api_key(api_key)
        fingerprint = await self._fingerprint_for(effective_api_key)
        effective_provider = provider or self.config.provider
        profile_key = str(profile_id) if profile_id is not None else None
        cache_key = (fingerprint, identity_id, effective_provider, profile_key)
        cached = self._credentials.get(cache_key)
        if cached and not force_refresh and await self._validate_credentials(cached):
            return cached

        token = await self._get_token(effective_api_key, fingerprint)
        encoded_identity_id = quote(identity_id, safe="").replace(".", "%2E")
        path = self.config.identity_token_path.format(identity_id=encoded_identity_id)
        body = {"provider": effective_provider}
        if profile_key:
            body["profile_id"] = profile_key

        client = await self._get_client()
        request_kwargs: dict[str, Any] = {
            "headers": {"Authorization": f"Bearer {token.value}"},
        }
        clean_body = {k: v for k, v in body.items() if v is not None}
        if clean_body:
            request_kwargs["json"] = clean_body
        response = await client.post(
            self._url(path),
            **request_kwargs,
        )
        self._raise_for_status(response, "identity token vend")
        credentials = self._parse_credentials(identity_id, response.json(), profile_key)
        self._remember(self._credentials, cache_key, credentials)
        return credentials

    async def get_headers(self) -> dict[str, str]:
        return {}

    def get_region_endpoint(
        self,
        region: str | None = None,
        provider: str | None = None,
    ) -> str:
        return self._default_endpoint(
            provider or self.config.provider,
            region or self.region,
        )

    def requires_identity_region_routing(self) -> bool:
        return True

    def headers_are_identity_specific(self) -> bool:
        return True

    def region_controlled_by_identity(self) -> bool:
        return True

    def set_current_api_key(self, api_key: str) -> ContextToken[str | None]:
        """Set an API-key override for the current async context."""

        return self._current_api_key.set(api_key)

    async def session_api_key_fingerprint(self, api_key: str) -> str:
        """Return the provider-local PBKDF2 discriminator for an API key."""
        return await self._fingerprint_for(api_key)

    def set_current_api_key_fingerprint(
        self, fingerprint: str
    ) -> ContextToken[str | None]:
        """Set a derived API-key fingerprint for the current async context."""
        return self._current_api_key_fingerprint.set(fingerprint)

    def reset_current_api_key_fingerprint(
        self, token: ContextToken[str | None]
    ) -> None:
        self._current_api_key_fingerprint.reset(token)

    def reset_current_api_key(self, token: ContextToken[str | None]) -> None:
        self._current_api_key.reset(token)

    async def close(self) -> None:
        self._tokens.clear()
        self._identities.clear()
        self._credentials.clear()
        if self._client and self._owns_client:
            await self._client.aclose()
        self._client = None

    def _coerce_config(
        self,
        config: KuudoProviderConfig | ProviderConfig | Any | None,
        kwargs: dict[str, Any],
    ) -> KuudoProviderConfig:
        values: dict[str, Any] = {}
        if config is None:
            values.update(kwargs)
        elif isinstance(config, KuudoProviderConfig):
            values.update(config.__dict__)
            values.update(kwargs)
        elif isinstance(config, dict):
            values.update(config)
            values.update(kwargs)
        else:
            for field_name in KuudoProviderConfig.__dataclass_fields__:
                if field_name in kwargs:
                    values[field_name] = kwargs[field_name]
                elif hasattr(config, "get"):
                    resolved = config.get(field_name)
                    if resolved is not None:
                        values[field_name] = resolved
                elif hasattr(config, field_name):
                    values[field_name] = getattr(config, field_name)

        return KuudoProviderConfig(
            base_url=values.get("base_url") or self._env("KUUDO_API_BASE_URL", "KUUDO_BASE_URL"),
            api_key=values.get("api_key") or self._env("KUUDO_API_KEY"),
            provider=values.get("provider"),
            region=values.get("region") or "na",
            timeout_seconds=float(values.get("timeout_seconds", 30.0)),
            token_exchange_path=values.get("token_exchange_path")
            or "/api/auth/token-exchange",
            identities_path=values.get("identities_path") or "/api/mcp/amazon/identities",
            identity_token_path=values.get("identity_token_path")
            or "/api/mcp/amazon/identities/{identity_id}/token",
            cache_buffer_seconds=int(values.get("cache_buffer_seconds", 300)),
            identity_cache_ttl_seconds=int(values.get("identity_cache_ttl_seconds", 300)),
            max_cache_entries=int(values.get("max_cache_entries", 128)),
            http_client=values.get("http_client"),
        )

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.config.timeout_seconds),
            )
            self._owns_client = True
        return self._client

    def _get_effective_api_key(self, api_key: str | None = None) -> str:
        effective = api_key or self._current_api_key.get() or self.config.api_key
        if not effective:
            raise KuudoConfigError("KUUDO_API_KEY or config.api_key must be configured")
        return effective

    def _require_base_url(self) -> str:
        if not self.config.base_url:
            raise KuudoConfigError(
                "KUUDO_API_BASE_URL, KUUDO_BASE_URL, or config.base_url must be configured"
            )
        return self.config.base_url.rstrip("/")

    def _url(self, path: str) -> str:
        base_url = self._require_base_url()
        if path.startswith("http://") or path.startswith("https://"):
            return path
        return f"{base_url}/{path.lstrip('/')}"

    @staticmethod
    def _env(*names: str) -> str | None:
        for name in names:
            value = os.getenv(name)
            if value:
                return value
        return None

    def _fingerprint(self, value: str) -> str:
        return hashlib.pbkdf2_hmac(
            "sha256",
            value.encode("utf-8"),
            self._fingerprint_salt,
            600_000,
            dklen=32,
        ).hex()

    async def _fingerprint_for(self, value: str) -> str:
        current_api_key = self._current_api_key.get()
        current_fingerprint = self._current_api_key_fingerprint.get()
        if (
            current_api_key
            and current_fingerprint
            and secrets.compare_digest(value, current_api_key)
        ):
            return current_fingerprint

        if value != self.config.api_key:
            return await asyncio.to_thread(self._fingerprint, value)

        if self._configured_api_key_fingerprint is None:
            async with self._configured_api_key_fingerprint_lock:
                if self._configured_api_key_fingerprint is None:
                    self._configured_api_key_fingerprint = await asyncio.to_thread(
                        self._fingerprint,
                        value,
                    )

        return self._configured_api_key_fingerprint

    @staticmethod
    def _cacheable_params(params: dict[str, Any]) -> tuple[tuple[str, str], ...]:
        return tuple(sorted((key, str(value)) for key, value in params.items()))

    @staticmethod
    def _aware(value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    async def _validate_credentials(self, credentials: AuthCredentials) -> bool:
        token = Token(value=credentials.access_token, expires_at=credentials.expires_at)
        return await self.validate_token(token)

    def _parse_credentials(
        self,
        identity_id: str,
        payload: dict[str, Any],
        profile_id: str | None,
    ) -> AuthCredentials:
        data = self._unwrap_payload(payload)
        access_token = self._first_string(data, "access_token", "token")
        if not access_token:
            raise KuudoAuthError("Kuudo token vending did not return an access token")

        provider = self._first_string(data, "provider") or self.config.provider
        region = (self._first_string(data, "region") or self.region).lower()
        client_id = self._first_string(data, "client_id")
        base_url = self._first_string(data, "base_url") or self._default_endpoint(
            provider,
            region,
        )
        expires_at = self._extract_expiration(data, access_token)
        selling_partner_id = self._first_string(data, "selling_partner_id")
        headers = self._build_identity_headers(
            provider=provider,
            access_token=access_token,
            client_id=client_id,
            profile_id=profile_id,
            selling_partner_id=selling_partner_id,
        )

        return AuthCredentials(
            identity_id=identity_id,
            access_token=access_token,
            token_type=self._first_string(data, "token_type") or "Bearer",
            expires_at=expires_at,
            base_url=base_url,
            headers=headers,
        )

    def _build_identity_headers(
        self,
        *,
        provider: str | None,
        access_token: str,
        client_id: str | None,
        profile_id: str | None,
        selling_partner_id: str | None,
    ) -> dict[str, str]:
        if provider == "amazon_sp_api" or selling_partner_id:
            return {"x-amz-access-token": access_token}

        if not client_id:
            raise KuudoAuthError("Kuudo token vending did not return an Amazon Ads client_id")

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Amazon-Advertising-API-ClientId": client_id,
        }
        if profile_id:
            headers["Amazon-Advertising-API-Scope"] = profile_id
        return headers

    @staticmethod
    def _parse_identity(item: dict[str, Any]) -> Identity:
        identity_id = item.get("id") or item.get("connection_id")
        if not identity_id:
            raise KuudoAuthError(
                "Kuudo identity payload did not include an id or connection_id"
            )

        attributes = item.get("attributes") if isinstance(item.get("attributes"), dict) else {}
        relationships = (
            item.get("relationships") if isinstance(item.get("relationships"), dict) else {}
        )
        account = item.get("account") if isinstance(item.get("account"), dict) else {}
        summary = (
            item.get("account_summary")
            if isinstance(item.get("account_summary"), dict)
            else {}
        )
        merged = {
            **attributes,
            **{
                k: v
                for k, v in item.items()
                if k not in {"attributes", "relationships"}
            },
        }
        display_name = (
            item.get("display_name")
            or item.get("name")
            or account.get("display_name")
            or account.get("name")
            or summary.get("display_name")
            or summary.get("name")
            or attributes.get("display_name")
            or attributes.get("name")
        )
        resolved_region = (
            item.get("region")
            or item.get("marketplace_region")
            or attributes.get("region")
            or attributes.get("marketplace_region")
        )
        for key, value in (
            ("provider", item.get("provider") or attributes.get("provider")),
            ("status", item.get("status") or attributes.get("status")),
            ("region", resolved_region),
            ("display_name", str(display_name) if display_name else None),
        ):
            if value is not None:
                merged.setdefault(key, value)
        merged.setdefault("raw", item)
        return Identity(
            id=str(identity_id),
            type=item.get("type") or "AmazonConnection",
            attributes=merged,
            relationships=relationships or None,
        )

    @staticmethod
    def _extract_items(payload: Any) -> list[dict[str, Any]]:
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        if not isinstance(payload, dict):
            return []
        for key in ("identities", "items", "data"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
        return []

    @staticmethod
    def _unwrap_payload(payload: dict[str, Any]) -> dict[str, Any]:
        data = payload.get("data")
        if isinstance(data, dict):
            attributes = data.get("attributes")
            if isinstance(attributes, dict):
                return {**data, **attributes}
            return data
        return payload

    def _extract_expiration(self, payload: dict[str, Any], token_value: str) -> datetime:
        expires_at_value = self._first_string(payload, "expires_at", "expiresAt")
        if expires_at_value:
            return self._parse_datetime(expires_at_value)

        expires_in = payload.get("expires_in")
        if expires_in is None:
            expires_in = payload.get("expiresIn")
        if isinstance(expires_in, (int, float)):
            return datetime.now(timezone.utc) + timedelta(seconds=float(expires_in))

        jwt_payload = self._decode_jwt_payload(token_value)
        exp = jwt_payload.get("exp")
        if exp is None:
            exp = jwt_payload.get("expires_at")
        if isinstance(exp, (int, float)):
            return datetime.fromtimestamp(float(exp), tz=timezone.utc)

        return datetime.now(timezone.utc) + timedelta(minutes=55)

    @staticmethod
    def _parse_datetime(value: str) -> datetime:
        normalized = value.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    @staticmethod
    def _decode_jwt_payload(token_value: str) -> dict[str, Any]:
        parts = token_value.split(".")
        if len(parts) < 2:
            return {}
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        try:
            decoded = base64.urlsafe_b64decode(padded.encode("utf-8"))
            payload = json.loads(decoded)
            return payload if isinstance(payload, dict) else {}
        except (ValueError, json.JSONDecodeError):
            return {}

    @staticmethod
    def _first_string(payload: dict[str, Any], *keys: Any) -> str | None:
        for key in keys:
            value: Any
            if isinstance(key, tuple):
                value = payload
                for part in key:
                    if not isinstance(value, dict):
                        value = None
                        break
                    value = value.get(part)
            else:
                value = payload.get(key)
            if value is not None and str(value).strip():
                return str(value)
        return None

    @staticmethod
    def _default_endpoint(provider: str | None, region: str) -> str:
        normalized_region = (region or "na").lower()
        if provider == "amazon_sp_api":
            return AMAZON_SP_API_ENDPOINTS.get(normalized_region, AMAZON_SP_API_ENDPOINTS["na"])
        return AMAZON_ADS_ENDPOINTS.get(normalized_region, AMAZON_ADS_ENDPOINTS["na"])

    @staticmethod
    def _raise_for_status(response: httpx.Response, operation: str) -> None:
        if response.status_code < 400:
            return
        try:
            payload = response.json()
            message = payload.get("message") or payload.get("error", {}).get("message")
        except (ValueError, AttributeError):
            message = response.text
        raise KuudoHTTPError(
            f"Kuudo {operation} failed with HTTP {response.status_code}: {message}"
        )

    def _remember(self, cache: OrderedDict[Any, Any], key: Any, value: Any) -> None:
        if key in cache:
            del cache[key]
        elif len(cache) >= self.config.max_cache_entries:
            cache.popitem(last=False)
        cache[key] = value
