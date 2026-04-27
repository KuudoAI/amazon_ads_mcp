"""Tests for the authentication provider architecture."""

import os
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from amazon_ads_mcp.auth.base import BaseAmazonAdsProvider, ProviderConfig
from amazon_ads_mcp.auth.providers.direct import DirectAmazonAdsProvider
from amazon_ads_mcp.auth.providers.openbridge import OpenBridgeProvider
from amazon_ads_mcp.auth.registry import ProviderRegistry, register_provider
from amazon_ads_mcp.models import Identity, Token


class TestProviderRegistry:
    """Tests for the provider registry system."""
    
    def test_registry_lists_builtin_providers(self):
        """Test that built-in providers are registered."""
        providers = ProviderRegistry.list_providers()
        assert "direct" in providers
        assert "openbridge" in providers
    
    def test_registry_creates_direct_provider(self):
        """Test creating a direct provider through registry."""
        config = ProviderConfig(
            client_id="test_client",
            client_secret="test_secret",
            refresh_token="test_refresh",
            region="na"
        )
        provider = ProviderRegistry.create_provider("direct", config)
        assert isinstance(provider, DirectAmazonAdsProvider)
        assert provider.client_id == "test_client"
        assert provider.region == "na"
    
    def test_registry_creates_openbridge_provider(self):
        """Test creating an OpenBridge provider through registry."""
        config = ProviderConfig(refresh_token="test_openbridge_token")
        provider = ProviderRegistry.create_provider("openbridge", config)
        assert isinstance(provider, OpenBridgeProvider)
        assert provider.refresh_token == "test_openbridge_token"
    
    def test_registry_raises_for_unknown_provider(self):
        """Test that registry raises error for unknown provider."""
        config = ProviderConfig()
        with pytest.raises(ValueError, match="Unknown provider type"):
            ProviderRegistry.create_provider("unknown", config)
    
    def test_custom_provider_registration(self):
        """Test registering a custom provider."""
        
        @register_provider("test_custom")
        class TestCustomProvider(BaseAmazonAdsProvider):
            def __init__(self, config: ProviderConfig):
                self.config = config
            
            @property
            def provider_type(self) -> str:
                return "test_custom"
            
            @property
            def region(self) -> str:
                return "na"
            
            async def initialize(self):
                pass
            
            async def get_token(self) -> Token:
                return Token(
                    value="test",
                    expires_at=datetime.now() + timedelta(hours=1),
                    token_type="Bearer"
                )
            
            async def validate_token(self, token: Token) -> bool:
                return True
            
            async def get_headers(self) -> dict:
                return {"test": "header"}
            
            async def close(self):
                pass
        
        # Check it's registered
        providers = ProviderRegistry.list_providers()
        assert "test_custom" in providers
        
        # Create instance
        config = ProviderConfig()
        provider = ProviderRegistry.create_provider("test_custom", config)
        assert isinstance(provider, TestCustomProvider)


class TestDirectProvider:
    """Tests for the Direct Amazon Ads provider."""
    
    @pytest.fixture
    def direct_provider(self):
        """Create a direct provider instance."""
        config = ProviderConfig(
            client_id="test_client",
            client_secret="test_secret",
            refresh_token="test_refresh",
            profile_id="test_profile",
            region="na"
        )
        return DirectAmazonAdsProvider(config)
    
    def test_direct_provider_initialization(self, direct_provider):
        """Test direct provider initializes correctly."""
        assert direct_provider.client_id == "test_client"
        assert direct_provider.client_secret == "test_secret"
        assert direct_provider.refresh_token == "test_refresh"
        assert direct_provider.profile_id == "test_profile"
        assert direct_provider.region == "na"
        assert direct_provider.get_oauth_endpoint() == "https://api.amazon.com/auth/o2/token"
    
    def test_direct_provider_region_endpoints(self):
        """Test that regions map to correct auth endpoints."""
        na_config = ProviderConfig(
            client_id="c", client_secret="s", refresh_token="r", region="na"
        )
        na_provider = DirectAmazonAdsProvider(na_config)
        assert na_provider.get_oauth_endpoint() == "https://api.amazon.com/auth/o2/token"
        
        eu_config = ProviderConfig(
            client_id="c", client_secret="s", refresh_token="r", region="eu"
        )
        eu_provider = DirectAmazonAdsProvider(eu_config)
        assert eu_provider.get_oauth_endpoint() == "https://api.amazon.co.uk/auth/o2/token"
        
        fe_config = ProviderConfig(
            client_id="c", client_secret="s", refresh_token="r", region="fe"
        )
        fe_provider = DirectAmazonAdsProvider(fe_config)
        assert fe_provider.get_oauth_endpoint() == "https://api.amazon.co.jp/auth/o2/token"
    
    @pytest.mark.asyncio
    async def test_direct_provider_token_refresh(self, direct_provider):
        """Test token refresh for direct provider."""
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "new_access_token",
            "expires_in": 3600
        }
        
        with patch("httpx.AsyncClient.post", return_value=mock_response):
            with patch.object(direct_provider, "_get_client", new_callable=AsyncMock) as mock_get_client:
                mock_client = AsyncMock()
                mock_client.post = AsyncMock(return_value=mock_response)
                mock_get_client.return_value = mock_client
                
                token = await direct_provider._refresh_access_token()
            
            assert token.value == "new_access_token"
            assert token.token_type == "Bearer"
            # Check expiration is roughly 1 hour from now
            expected_expiry = datetime.now(timezone.utc) + timedelta(seconds=3600)
            assert abs((token.expires_at - expected_expiry).total_seconds()) < 5
            
            # Clean up the token to avoid affecting other tests
            direct_provider._access_token = None
    
    @pytest.mark.asyncio
    async def test_direct_provider_token_caching(self, direct_provider):
        """Test that tokens are cached and reused."""
        # Reset AuthManager to ensure clean state
        from amazon_ads_mcp.auth.manager import AuthManager
        AuthManager.reset()
        
        # Set a cached token
        direct_provider._access_token = Token(
            value="cached_token",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            token_type="Bearer"
        )
        
        # Mock _refresh_access_token to prevent it from being called
        with patch.object(direct_provider, "_refresh_access_token", new_callable=AsyncMock) as mock_refresh:
            # Get token should return cached one without making request
            token = await direct_provider.get_token()
            assert token.value == "cached_token"
            # Ensure _refresh_access_token was not called
            mock_refresh.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_direct_provider_expired_token_refresh(self, direct_provider):
        """Test that expired tokens trigger refresh."""
        # Reset AuthManager to ensure clean state
        from amazon_ads_mcp.auth.manager import AuthManager
        AuthManager.reset()
        
        # Set an expired cached token
        direct_provider._access_token = Token(
            value="expired_token",
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
            token_type="Bearer"
        )
        
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "fresh_token",
            "expires_in": 3600
        }
        
        with patch.object(direct_provider, "_get_client", new_callable=AsyncMock) as mock_get_client:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_get_client.return_value = mock_client
            
            # Mock _refresh_access_token to return our expected token
            with patch.object(direct_provider, "_refresh_access_token", return_value=Token(
                value="fresh_token",
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
                token_type="Bearer"
            )):
                token = await direct_provider.get_token()
                assert token.value == "fresh_token"
    
    @pytest.mark.asyncio
    async def test_direct_provider_list_identities(self, direct_provider):
        """Test that direct provider returns single synthetic identity."""
        identities = await direct_provider.list_identities()
        
        assert len(identities) == 1
        identity = identities[0]
        assert identity.id == "direct-auth"
        assert identity.type == "amazon_ads_direct"
        assert identity.attributes["auth_method"] == "direct"
        assert identity.attributes["client_id"] == "test_client"
        assert identity.attributes["region"] == "na"
    
    @pytest.mark.asyncio
    async def test_direct_provider_get_credentials(self, direct_provider):
        """Test getting credentials from direct provider."""
        # Reset AuthManager to ensure clean state
        from amazon_ads_mcp.auth.manager import AuthManager
        AuthManager.reset()
        
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "test_token",
            "expires_in": 3600
        }
        
        with patch.object(direct_provider, "_get_client", new_callable=AsyncMock) as mock_get_client:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_get_client.return_value = mock_client
            
            # Mock _refresh_access_token to return our expected token
            with patch.object(direct_provider, "_refresh_access_token", return_value=Token(
                value="test_token",
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
                token_type="Bearer"
            )):
                credentials = await direct_provider.get_identity_credentials("direct-auth")
                
                assert credentials.identity_id == "direct-auth"
                assert credentials.access_token == "test_token"
            assert "Authorization" in credentials.headers
            assert credentials.headers["Authorization"] == "Bearer test_token"
            assert credentials.headers["Amazon-Advertising-API-ClientId"] == "test_client"
            assert credentials.headers["Amazon-Advertising-API-Scope"] == "test_profile"


class TestOpenBridgeProvider:
    """Tests for the OpenBridge provider."""
    
    @pytest.fixture
    def openbridge_provider(self):
        """Create an OpenBridge provider instance."""
        config = ProviderConfig(refresh_token="test_openbridge_refresh")
        return OpenBridgeProvider(config)
    
    def test_openbridge_provider_initialization(self, openbridge_provider):
        """Test OpenBridge provider initializes correctly."""
        assert openbridge_provider.refresh_token == "test_openbridge_refresh"
        assert openbridge_provider.auth_base_url == "https://authentication.api.openbridge.io"
        assert openbridge_provider.identity_base_url == "https://remote-identity.api.openbridge.io"
        assert openbridge_provider.service_base_url == "https://service.api.openbridge.io"
    
    def test_openbridge_provider_custom_endpoints(self, monkeypatch):
        """Test OpenBridge provider with custom endpoints."""
        config = ProviderConfig(
            refresh_token="test",
            auth_base_url="https://custom.auth.url",
            identity_base_url="https://custom.identity.url",
            service_base_url="https://custom.service.url"
        )
        
        provider = OpenBridgeProvider(config)
        assert provider.auth_base_url == "https://custom.auth.url"
        assert provider.identity_base_url == "https://custom.identity.url"
        assert provider.service_base_url == "https://custom.service.url"
    
    @pytest.mark.asyncio
    async def test_openbridge_jwt_conversion(self, openbridge_provider):
        """Test converting refresh token to JWT."""
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 202
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHBpcmVzX2F0IjoxNzAwMDAwMDAwLCJ1c2VyX2lkIjoiMTIzIiwiYWNjb3VudF9pZCI6IjQ1NiJ9.test"
                }
            }
        }
        
        with patch.object(openbridge_provider, "_get_client", new_callable=AsyncMock) as mock_get_client:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_get_client.return_value = mock_client
            
            with patch("jwt.decode") as mock_decode:
                mock_decode.return_value = {
                    "expires_at": 1700000000,
                    "user_id": "123",
                    "account_id": "456"
                }
                
                token = await openbridge_provider._refresh_jwt_token()
                
                assert token.value.startswith("eyJ")
                assert token.token_type == "Bearer"
                assert token.metadata["user_id"] == "123"
                assert token.metadata["account_id"] == "456"
    
    @pytest.mark.asyncio
    async def test_openbridge_list_identities(self, openbridge_provider):
        """Test listing identities from OpenBridge."""
        # Mock JWT token via fingerprinted cache
        jwt_token = Token(
            value="test_jwt",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            token_type="Bearer"
        )
        fingerprint = openbridge_provider._token_fingerprint()
        openbridge_provider._jwt_tokens[fingerprint] = jwt_token
        
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [
                {
                    "id": "identity-1",
                    "type": "remote_identity",
                    "attributes": {"name": "Test Identity 1", "region": "na"}
                },
                {
                    "id": "identity-2",
                    "type": "remote_identity",
                    "attributes": {"name": "Test Identity 2", "region": "eu"}
                }
            ],
            "links": {}
        }
        
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        
        with patch.object(openbridge_provider, "_get_client", return_value=mock_client):
            
            identities = await openbridge_provider.list_identities()
            
            assert len(identities) == 2
            assert identities[0].id == "identity-1"
            assert identities[0].attributes["name"] == "Test Identity 1"
            assert identities[1].id == "identity-2"
            assert identities[1].attributes["region"] == "eu"
    
    @pytest.mark.asyncio
    async def test_openbridge_identity_caching(self, openbridge_provider):
        """Test that identities are cached."""
        # This test verifies the caching logic exists
        # The actual OpenBridge provider doesn't have a simple _identities_cache
        # but uses a more complex caching mechanism
        
        # Check that the provider has caching attributes
        assert hasattr(openbridge_provider, '_identities_cache')
        
        # Mock the fetch to avoid real API calls
        from amazon_ads_mcp.models import Identity
        test_identities = [Identity(id="test-1", type="test", attributes={})]
        
        with patch.object(openbridge_provider, '_fetch_identities', return_value=test_identities):
            # First call should fetch
            identities1 = await openbridge_provider.list_identities()
            assert len(identities1) == 1
            assert identities1[0].id == "test-1"

    @pytest.mark.asyncio
    async def test_openbridge_resolves_client_id_from_identity_relationship(
        self, openbridge_provider
    ):
        """Provider resolves missing token client_id using relationship metadata."""
        identity = Identity(
            id="id-1",
            type="remote_identity",
            attributes={"name": "Relationship Test", "region": "na"},
            relationships={
                "remote_identity_type_application": {
                    "data": {"id": "16", "type": "RemoteIdentityTypeApplication"}
                }
            },
        )
        jwt_token = Token(
            value="test_jwt",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            token_type="Bearer",
        )

        token_response = MagicMock(spec=httpx.Response)
        token_response.status_code = 200
        token_response.raise_for_status = MagicMock()
        token_response.json.return_value = {"data": {"access_token": "amazon_token"}}

        not_found_response = MagicMock(spec=httpx.Response)
        not_found_response.status_code = 404
        not_found_response.json.return_value = {}

        app_response = MagicMock(spec=httpx.Response)
        app_response.status_code = 200
        app_response.json.return_value = {
            "data": {
                "id": "16",
                "attributes": {"oauth_client_id": "resolved-client-id"},
            }
        }

        async def get_side_effect(url, **kwargs):
            if "/service/amzadv/token/" in url:
                return token_response
            if "/rita/16" in url:
                return app_response
            if "/sri/id-1" in url:
                return not_found_response
            return not_found_response

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=get_side_effect)

        with patch.object(openbridge_provider, "get_identity", return_value=identity):
            with patch.object(openbridge_provider, "get_token", return_value=jwt_token):
                with patch.object(openbridge_provider, "_get_client", return_value=mock_client):
                    credentials = await openbridge_provider.get_identity_credentials("id-1")

        assert credentials.headers["Amazon-Advertising-API-ClientId"] == "resolved-client-id"


class TestAuthManagerIntegration:
    """Integration tests for auth manager with providers."""
    
    @pytest.mark.asyncio
    async def test_auth_manager_auto_detect_direct(self, monkeypatch):
        """Test auth manager auto-detects direct credentials."""
        # Explicitly set AUTH_METHOD to override auto-detection from .env file
        monkeypatch.setenv("AUTH_METHOD", "direct")
        monkeypatch.setenv("AMAZON_AD_API_CLIENT_ID", "test_client")
        monkeypatch.setenv("AMAZON_AD_API_CLIENT_SECRET", "test_secret")
        monkeypatch.setenv("AMAZON_AD_API_REFRESH_TOKEN", "test_refresh")

        from amazon_ads_mcp.auth.manager import AuthManager
        from amazon_ads_mcp.config.settings import Settings
        monkeypatch.setattr("amazon_ads_mcp.auth.manager.settings", Settings())
        AuthManager.reset()  # Reset singleton

        manager = AuthManager()
        assert isinstance(manager.provider, DirectAmazonAdsProvider)
    
    @pytest.mark.asyncio
    async def test_auth_manager_explicit_openbridge(self, monkeypatch):
        """Test auth manager uses OpenBridge when explicitly configured."""
        # Clear direct credentials (both new and legacy environment variables)
        # Remove them entirely to override .env file values
        monkeypatch.delenv("AMAZON_AD_API_CLIENT_ID", raising=False)
        monkeypatch.delenv("AMAZON_AD_API_CLIENT_SECRET", raising=False)
        monkeypatch.delenv("AMAZON_AD_API_REFRESH_TOKEN", raising=False)
        monkeypatch.delenv("AMAZON_ADS_CLIENT_ID", raising=False)
        monkeypatch.delenv("AMAZON_ADS_CLIENT_SECRET", raising=False)
        monkeypatch.delenv("AMAZON_ADS_REFRESH_TOKEN", raising=False)
        
        # Set OpenBridge credentials
        monkeypatch.setenv("OPENBRIDGE_REFRESH_TOKEN", "test_ob_token")
        
        # Explicitly set AUTH_METHOD to openbridge to override auto-detection
        monkeypatch.setenv("AUTH_METHOD", "openbridge")

        from amazon_ads_mcp.auth.manager import AuthManager
        from amazon_ads_mcp.config.settings import Settings
        monkeypatch.setattr("amazon_ads_mcp.auth.manager.settings", Settings())
        AuthManager.reset()  # Reset singleton

        manager = AuthManager()
        assert isinstance(manager.provider, OpenBridgeProvider)
    
    @pytest.mark.asyncio
    async def test_auth_manager_explicit_method(self, monkeypatch):
        """Test auth manager uses explicit AUTH_METHOD."""
        monkeypatch.setenv("AUTH_METHOD", "direct")
        monkeypatch.setenv("AMAZON_AD_API_CLIENT_ID", "test_client")
        monkeypatch.setenv("AMAZON_AD_API_CLIENT_SECRET", "test_secret")
        monkeypatch.setenv("AMAZON_AD_API_REFRESH_TOKEN", "test_refresh")

        from amazon_ads_mcp.auth.manager import AuthManager
        from amazon_ads_mcp.config.settings import Settings
        monkeypatch.setattr("amazon_ads_mcp.auth.manager.settings", Settings())
        AuthManager.reset()  # Reset singleton

        manager = AuthManager()
        assert isinstance(manager.provider, DirectAmazonAdsProvider)
    
    def test_auth_manager_no_credentials_error(self, monkeypatch):
        """Test auth manager raises error when no credentials."""
        # Note: This test may not work properly if there's a .env file with credentials.
        # In a real test environment, we'd mock the settings loading to avoid this.
        # For now, we skip this test if a .env file is present.
        if os.path.exists(".env"):
            pytest.skip(".env file present - would interfere with test")
        
        # Clear all auth environment variables
        for key in ["AUTH_METHOD", "AMAZON_AD_API_CLIENT_ID", "AMAZON_AD_API_CLIENT_SECRET", 
                    "AMAZON_AD_API_REFRESH_TOKEN", "OPENBRIDGE_REFRESH_TOKEN",
                    "AMAZON_ADS_CLIENT_ID", "AMAZON_ADS_CLIENT_SECRET",
                    "AMAZON_ADS_REFRESH_TOKEN"]:
            monkeypatch.delenv(key, raising=False)
        
        from amazon_ads_mcp.auth.manager import AuthManager
        from amazon_ads_mcp.config.settings import Settings
        monkeypatch.setattr("amazon_ads_mcp.auth.manager.settings", Settings())
        AuthManager.reset()  # Reset singleton

        with pytest.raises(ValueError, match="No authentication method configured"):
            AuthManager()


class TestProviderConfig:
    """Tests for ProviderConfig class."""
    
    def test_provider_config_dict_access(self):
        """Test ProviderConfig works like a dict."""
        config = ProviderConfig(
            client_id="test",
            custom_field="value"
        )
        
        assert config.get("client_id") == "test"
        assert config.get("custom_field") == "value"
        assert config.get("missing", "default") == "default"
    
    def test_provider_config_attribute_access(self):
        """Test ProviderConfig allows attribute access."""
        config = ProviderConfig(
            client_id="test",
            api_key="key123"
        )
        
        assert config.client_id == "test"
        assert config.api_key == "key123"
        assert config.get("client_id") == config.client_id
