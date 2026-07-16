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
from amazon_ads_mcp.auth.providers.kuudo import KuudoAuthError
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


@pytest.mark.asyncio
async def test_kuudo_adapter_omits_openbridge_identity_type_query_parameter():
    identity_requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/auth/token-exchange":
            return httpx.Response(
                200,
                json={"access_token": "platform-jwt", "expires_in": 3600},
            )
        identity_requests.append(request)
        return httpx.Response(200, json={"identities": []})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        provider = KuudoAmazonAdsProvider(
            ProviderConfig(
                base_url="https://app.kuudo.test",
                api_key="sk_test",
                provider="amazon_ads",
                http_client=client,
            )
        )

        await provider.list_identities(identity_type="14", force_refresh=True)

    assert len(identity_requests) == 1
    assert identity_requests[0].url.params["provider"] == "amazon_ads"
    assert "identity_type" not in identity_requests[0].url.params


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


def test_kuudo_fingerprint_is_stable_within_instance_and_scoped_between_instances():
    config = ProviderConfig(
        base_url="https://app.kuudo.test",
        api_key="client-supplied-token",
        provider="amazon_ads",
    )
    first_provider = KuudoAmazonAdsProvider(config)
    second_provider = KuudoAmazonAdsProvider(config)

    first_fingerprint = first_provider._fingerprint("client-supplied-token")

    assert first_fingerprint == first_provider._fingerprint("client-supplied-token")
    assert first_fingerprint != second_provider._fingerprint("client-supplied-token")


def test_kuudo_api_key_context_override_is_scoped_to_provider_instance():
    config = ProviderConfig(
        base_url="https://app.kuudo.test",
        api_key="configured-token",
        provider="amazon_ads",
    )
    first_provider = KuudoAmazonAdsProvider(config)
    second_provider = KuudoAmazonAdsProvider(config)

    context_token = first_provider.set_current_api_key("request-token")
    try:
        assert first_provider._get_effective_api_key() == "request-token"
        assert second_provider._get_effective_api_key() == "configured-token"
    finally:
        first_provider.reset_current_api_key(context_token)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("identity_id", "encoded_segment"),
    [
        ("connection/child", "connection%2Fchild"),
        ("connection?admin=true", "connection%3Fadmin%3Dtrue"),
        ("connection#fragment", "connection%23fragment"),
        (".", "%2E"),
        ("..", "%2E%2E"),
    ],
)
async def test_kuudo_identity_token_url_encodes_identity_id_as_one_path_segment(
    identity_id,
    encoded_segment,
):
    vend_paths: list[bytes] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/auth/token-exchange":
            return httpx.Response(
                200,
                json={"access_token": "platform-jwt", "expires_in": 3600},
            )
        vend_paths.append(request.url.raw_path)
        return httpx.Response(
            200,
            json={
                "access_token": "amazon-access-token",
                "expires_in": 3600,
                "client_id": "amazon-client-id",
                "provider": "amazon_ads",
                "region": "na",
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        provider = KuudoAmazonAdsProvider(
            ProviderConfig(
                base_url="https://app.kuudo.test",
                api_key="sk_test",
                provider="amazon_ads",
                http_client=client,
            )
        )

        await provider.get_identity_credentials(identity_id)

    assert vend_paths == [
        f"/api/mcp/amazon/identities/{encoded_segment}/token".encode()
    ]


@pytest.mark.asyncio
async def test_kuudo_rejects_empty_identity_id_before_sending_a_request():
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/api/auth/token-exchange":
            return httpx.Response(
                200,
                json={"access_token": "platform-jwt", "expires_in": 3600},
            )
        return httpx.Response(
            200,
            json={
                "access_token": "amazon-access-token",
                "expires_in": 3600,
                "client_id": "amazon-client-id",
                "provider": "amazon_ads",
                "region": "na",
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        provider = KuudoAmazonAdsProvider(
            ProviderConfig(
                base_url="https://app.kuudo.test",
                api_key="sk_test",
                provider="amazon_ads",
                http_client=client,
            )
        )

        with pytest.raises(KuudoAuthError, match="identity_id must be nonempty"):
            await provider.get_identity_credentials("")

    assert requests == []


@pytest.mark.asyncio
async def test_kuudo_credential_cache_is_scoped_by_effective_provider():
    vend_providers: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/auth/token-exchange":
            return httpx.Response(
                200,
                json={"access_token": "platform-jwt", "expires_in": 3600},
            )

        requested_provider = json.loads(request.content)["provider"]
        vend_providers.append(requested_provider)
        if requested_provider == "amazon_sp_api":
            return httpx.Response(
                200,
                json={
                    "access_token": "sp-api-access-token",
                    "expires_in": 3600,
                    "provider": "amazon_sp_api",
                    "region": "na",
                    "selling_partner_id": "seller-1",
                },
            )
        return httpx.Response(
            200,
            json={
                "access_token": "ads-access-token",
                "expires_in": 3600,
                "client_id": "amazon-client-id",
                "provider": "amazon_ads",
                "region": "na",
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        provider = KuudoAmazonAdsProvider(
            ProviderConfig(
                base_url="https://app.kuudo.test",
                api_key="sk_test",
                provider="amazon_ads",
                http_client=client,
            )
        )

        ads_credentials = await provider.get_identity_credentials(
            "connection-1",
            provider="amazon_ads",
            profile_id="profile-1",
        )
        sp_api_credentials = await provider.get_identity_credentials(
            "connection-1",
            provider="amazon_sp_api",
            profile_id="profile-1",
        )
        cached_ads_credentials = await provider.get_identity_credentials(
            "connection-1",
            provider="amazon_ads",
            profile_id="profile-1",
        )
        cached_sp_api_credentials = await provider.get_identity_credentials(
            "connection-1",
            provider="amazon_sp_api",
            profile_id="profile-1",
        )

    assert ads_credentials.access_token == "ads-access-token"
    assert sp_api_credentials.access_token == "sp-api-access-token"
    assert cached_ads_credentials.access_token == "ads-access-token"
    assert cached_sp_api_credentials.access_token == "sp-api-access-token"
    assert vend_providers == ["amazon_ads", "amazon_sp_api"]


def test_kuudo_rejects_identity_payload_without_identifier():
    with pytest.raises(
        KuudoAuthError,
        match="identity payload did not include an id or connection_id",
    ):
        KuudoAmazonAdsProvider._parse_identity(
            {"display_name": "Malformed connection"}
        )
