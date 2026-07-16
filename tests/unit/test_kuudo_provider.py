"""Activation and contract tests for the Kuudo auth provider."""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

from amazon_ads_mcp.auth.base import (
    BaseAmazonAdsProvider,
    BaseIdentityProvider,
    ProviderConfig,
)
from amazon_ads_mcp.auth.providers.kuudo_ads import KuudoAmazonAdsProvider
from amazon_ads_mcp.auth.registry import ProviderRegistry
from amazon_ads_mcp.config.settings import Settings
from amazon_ads_mcp.models import AuthCredentials, Identity, Token
from amazon_ads_mcp.models.builtin_responses import GetRegionResponse


def test_kuudo_provider_is_registered():
    provider_class = ProviderRegistry.get_provider_class("kuudo")

    assert provider_class is KuudoAmazonAdsProvider
    provider = ProviderRegistry.create_provider(
        "kuudo",
        ProviderConfig(
            base_url="https://app.kuudo.test",
            api_key="sk_test",
            provider="amazon_ads",
        ),
    )
    assert isinstance(provider, BaseAmazonAdsProvider)
    assert isinstance(provider, BaseIdentityProvider)


def test_settings_accept_kuudo_configuration(monkeypatch):
    monkeypatch.setenv("AUTH_METHOD", "kuudo")
    monkeypatch.setenv("KUUDO_API_BASE_URL", "https://app.kuudo.test")
    monkeypatch.setenv("KUUDO_API_KEY", "sk_test")
    monkeypatch.setenv("KUUDO_PROVIDER", "amazon_ads")
    monkeypatch.setenv("KUUDO_REMOTE_IDENTITY_ID", "connection-1")

    configured = Settings()

    assert configured.auth_method == "kuudo"
    assert configured.kuudo_api_base_url == "https://app.kuudo.test"
    assert configured.kuudo_api_key == "sk_test"
    assert configured.kuudo_provider == "amazon_ads"
    assert configured.kuudo_remote_identity_id == "connection-1"

    region_response = GetRegionResponse(
        success=True,
        region="na",
        region_name="North America",
        api_endpoint="https://advertising-api.amazon.com",
        auth_method="kuudo",
    )
    assert region_response.auth_method == "kuudo"


@pytest.mark.asyncio
async def test_kuudo_provider_adapts_identity_and_credentials_to_project_models():
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/api/auth/token-exchange":
            assert request.headers["authorization"] == "Bearer sk_test"
            return httpx.Response(
                200,
                json={"access_token": "platform-jwt", "expires_in": 3600},
            )
        if request.url.path == "/api/mcp/amazon/identities":
            assert request.headers["authorization"] == "Bearer platform-jwt"
            assert request.url.params["provider"] == "amazon_ads"
            return httpx.Response(
                200,
                json={
                    "identities": [
                        {
                            "id": "connection-1",
                            "type": "AmazonConnection",
                            "provider": "amazon_ads",
                            "region": "eu",
                            "display_name": "EU Ads account",
                        }
                    ]
                },
            )
        if request.url.path == "/api/mcp/amazon/identities/connection-1/token":
            assert request.headers["authorization"] == "Bearer platform-jwt"
            assert json.loads(request.content) == {"provider": "amazon_ads"}
            return httpx.Response(
                200,
                json={
                    "access_token": "amazon-access-token",
                    "expires_in": 3600,
                    "client_id": "amazon-client-id",
                    "provider": "amazon_ads",
                    "region": "eu",
                },
            )
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    provider = KuudoAmazonAdsProvider(
        ProviderConfig(
            base_url="https://app.kuudo.test",
            api_key="sk_test",
            provider="amazon_ads",
            http_client=client,
        )
    )

    token = await provider.get_token()
    identities = await provider.list_identities()
    credentials = await provider.get_identity_credentials("connection-1")

    assert isinstance(token, Token)
    assert isinstance(identities[0], Identity)
    assert identities[0].attributes["region"] == "eu"
    assert isinstance(credentials, AuthCredentials)
    assert credentials.base_url == "https://advertising-api-eu.amazon.com"
    assert credentials.headers == {
        "Authorization": "Bearer amazon-access-token",
        "Amazon-Advertising-API-ClientId": "amazon-client-id",
    }
    assert [request.url.path for request in requests] == [
        "/api/auth/token-exchange",
        "/api/mcp/amazon/identities",
        "/api/mcp/amazon/identities/connection-1/token",
    ]

    await provider.close()
    await client.aclose()


def test_auth_manager_builds_kuudo_provider(monkeypatch):
    monkeypatch.setenv("AUTH_METHOD", "kuudo")
    monkeypatch.setenv("KUUDO_API_BASE_URL", "https://app.kuudo.test")
    monkeypatch.setenv("KUUDO_API_KEY", "sk_test")
    monkeypatch.setenv("KUUDO_REMOTE_IDENTITY_ID", "connection-1")

    from amazon_ads_mcp.auth import manager as manager_module

    monkeypatch.setattr(manager_module, "settings", Settings())
    manager_module.AuthManager.reset()
    manager = manager_module.AuthManager()

    assert isinstance(manager.provider, KuudoAmazonAdsProvider)
    assert manager.provider.config.base_url == "https://app.kuudo.test"
    assert manager.provider.config.api_key == "sk_test"
    assert manager._default_identity_id == "connection-1"

    manager_module.AuthManager.reset()


@pytest.mark.asyncio
async def test_kuudo_registers_remote_identity_tools(monkeypatch):
    from amazon_ads_mcp.server import builtin_tools

    common_registrars = (
        "register_envelope_contract_tools",
        "register_profile_tools",
        "register_profile_listing_tools",
        "register_region_tools",
        "register_download_tools",
        "register_report_catalog_tools",
        "register_sampling_tools",
    )
    for registrar in common_registrars:
        monkeypatch.setattr(builtin_tools, registrar, AsyncMock())
    identity_registrar = AsyncMock()
    oauth_registrar = AsyncMock()
    monkeypatch.setattr(builtin_tools, "register_identity_tools", identity_registrar)
    monkeypatch.setattr(builtin_tools, "register_oauth_tools_builtin", oauth_registrar)
    monkeypatch.setattr(
        builtin_tools,
        "get_auth_manager",
        lambda: SimpleNamespace(provider=SimpleNamespace(provider_type="kuudo")),
    )

    server = SimpleNamespace()
    await builtin_tools.register_all_builtin_tools(server)

    identity_registrar.assert_awaited_once_with(server)
    oauth_registrar.assert_not_awaited()
