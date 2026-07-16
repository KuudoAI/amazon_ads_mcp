"""Amazon Ads project adapter for the reusable Kuudo auth provider."""

from __future__ import annotations

from typing import Any

from ...models import AuthCredentials, Identity, Token
from ..base import BaseAmazonAdsProvider, BaseIdentityProvider, ProviderConfig
from ..registry import register_provider
from .kuudo import KuudoAuthProvider


@register_provider("kuudo")
class KuudoAmazonAdsProvider(
    KuudoAuthProvider,
    BaseAmazonAdsProvider,
    BaseIdentityProvider,
):
    """Adapt Kuudo credentials to Amazon Ads MCP provider contracts."""

    def __init__(self, config: ProviderConfig):
        super().__init__(config)

    async def get_token(self, api_key: str | None = None) -> Token:
        token = await super().get_token(api_key=api_key)
        return Token(
            value=token.value,
            expires_at=token.expires_at,
            token_type=token.token_type,
            scope=token.scope,
            metadata=token.metadata,
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
        identities = await super().list_identities(
            provider=provider,
            api_key=api_key,
            force_refresh=force_refresh,
            **params,
        )
        return [self._to_project_identity(identity) for identity in identities]

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
        credentials = await super().get_identity_credentials(
            identity_id,
            api_key=api_key,
            provider=provider,
            profile_id=profile_id,
            force_refresh=force_refresh,
        )
        return AuthCredentials(
            identity_id=credentials.identity_id,
            access_token=credentials.access_token,
            token_type=credentials.token_type,
            expires_at=credentials.expires_at,
            base_url=credentials.base_url,
            headers=credentials.headers,
        )

    @staticmethod
    def _to_project_identity(identity: Any) -> Identity:
        attributes = dict(identity.attributes)
        for key in ("provider", "status", "region", "display_name"):
            value = getattr(identity, key, None)
            if value is not None:
                attributes.setdefault(key, value)
        if identity.raw:
            attributes.setdefault("raw", identity.raw)
        return Identity(
            id=identity.id,
            type=identity.type,
            attributes=attributes,
            relationships=identity.relationships or None,
        )
