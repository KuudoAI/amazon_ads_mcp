"""Unit tests for AuthenticatedClient.

Tests the header scrubbing, injection, and media type negotiation
functionality of the AuthenticatedClient.
"""

import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch
import httpx

from amazon_ads_mcp.utils.http_client import AuthenticatedClient
from amazon_ads_mcp.utils.header_resolver import HeaderNameResolver
from amazon_ads_mcp.utils.media import MediaTypeRegistry


@pytest.fixture
def mock_auth_manager():
    """Create a mock auth manager."""
    manager = AsyncMock()
    manager.get_headers = AsyncMock(return_value={
        "Authorization": "Bearer test-token",
        "Amazon-Advertising-API-ClientId": "test-client-id",
        "Amazon-Advertising-API-Scope": "test-profile-id"
    })
    # Mock provider capabilities (default to False for non-OpenBridge provider)
    manager.provider = MagicMock()
    manager.provider.requires_identity_region_routing = MagicMock(return_value=False)
    manager.provider.headers_are_identity_specific = MagicMock(return_value=False)
    manager.provider.region_controlled_by_identity = MagicMock(return_value=False)
    manager.provider.provider_type = "direct"
    manager.get_active_identity = MagicMock(return_value=None)
    return manager


@pytest.fixture
def mock_media_registry():
    """Create a mock media registry."""
    registry = MagicMock(spec=MediaTypeRegistry)
    # New API: resolve(method, url) -> (content_type, accepts)
    registry.resolve = MagicMock(return_value=(None, ["application/json"]))
    return registry


@pytest.fixture
def mock_header_resolver():
    """Create a mock header resolver."""
    return HeaderNameResolver()


@pytest_asyncio.fixture
async def authenticated_client(mock_auth_manager, mock_media_registry, mock_header_resolver):
    """Create an authenticated client with mocks."""
    client = AuthenticatedClient(
        auth_manager=mock_auth_manager,
        media_registry=mock_media_registry,
        header_resolver=mock_header_resolver
    )
    return client


@pytest.mark.asyncio
class TestAuthenticatedClient:
    """Test suite for AuthenticatedClient."""
    
    async def test_header_scrubbing(self, authenticated_client):
        """Test that polluted headers are removed."""
        # Create a request with polluted headers
        request = httpx.Request(
            method="GET",
            url="https://advertising-api.amazon.com/test",
            headers={
                "authorization": "Bearer polluted-token",  # Should be removed
                "amazon-ads-clientid": "polluted-client",  # Should be removed
                "accept": "application/json",  # Should be kept
                "content-type": "application/json",  # Should be kept
            }
        )
        
        # Mock the parent send method
        with patch.object(httpx.AsyncClient, 'send', new_callable=AsyncMock) as mock_send:
            mock_response = httpx.Response(200, json={"success": True})
            mock_send.return_value = mock_response
            
            # Send the request
            await authenticated_client.send(request)
            
            # Verify headers were scrubbed and replaced
            sent_request = mock_send.call_args[0][0]
            assert "authorization" in sent_request.headers
            assert sent_request.headers["authorization"] == "Bearer test-token"
            assert sent_request.headers.get("Amazon-Advertising-API-ClientId") == "test-client-id"
    
    async def test_header_injection(self, authenticated_client, mock_auth_manager):
        """Test that auth headers are properly injected."""
        request = httpx.Request(
            method="POST",
            url="https://advertising-api.amazon.com/campaigns",
            headers={
                "accept": "application/json",
                "content-type": "application/json",
            }
        )
        
        with patch.object(httpx.AsyncClient, 'send', new_callable=AsyncMock) as mock_send:
            mock_response = httpx.Response(200, json={"id": "123"})
            mock_send.return_value = mock_response
            
            await authenticated_client.send(request)
            
            # Verify auth manager was called
            mock_auth_manager.get_headers.assert_called_once()
            
            # Verify headers were injected
            sent_request = mock_send.call_args[0][0]
            assert sent_request.headers.get("authorization") == "Bearer test-token"
            assert sent_request.headers.get("Amazon-Advertising-API-ClientId") is not None
    
    async def test_idempotent_injection(self, authenticated_client):
        """Test that headers are only injected once."""
        request = httpx.Request(
            method="GET",
            url="https://advertising-api.amazon.com/test"
        )
        
        # Mark as already processed
        request.extensions["auth_injected"] = True
        
        with patch.object(authenticated_client, '_inject_headers', new_callable=AsyncMock) as mock_inject:
            with patch.object(httpx.AsyncClient, 'send', new_callable=AsyncMock) as mock_send:
                mock_response = httpx.Response(200)
                mock_send.return_value = mock_response
                
                await authenticated_client.send(request)
                
                # Verify injection was skipped
                mock_inject.assert_not_called()
    
    async def test_media_type_negotiation(self, authenticated_client, mock_media_registry):
        """Test that media types are negotiated from registry."""
        request = httpx.Request(
            method="GET",
            url="https://advertising-api.amazon.com/reports/12345/download"
        )
        
        # Configure media registry to advertise the vendor type in accepts
        mock_media_registry.resolve.return_value = (
            None,
            [
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                "application/json",
            ],
        )
        
        with patch.object(httpx.AsyncClient, 'send', new_callable=AsyncMock) as mock_send:
            mock_response = httpx.Response(200)
            mock_send.return_value = mock_response
            
            await authenticated_client.send(request)
            
            # Verify media type was set
            sent_request = mock_send.call_args[0][0]
            assert sent_request.headers.get("accept") == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    
    async def test_region_routing(self, authenticated_client):
        """Test that region-specific routing is applied."""
        # Test EU region routing
        request = httpx.Request(
            method="GET",
            url="https://advertising-api.amazon.com/profiles"
        )
        
        from amazon_ads_mcp.utils.http_client import set_region_override
        set_region_override("eu")
        with patch.object(httpx.AsyncClient, 'send', new_callable=AsyncMock) as mock_send:
            mock_response = httpx.Response(200, json=[])
            mock_send.return_value = mock_response
            
            await authenticated_client.send(request)
            
            # Verify URL was updated to EU endpoint
            sent_request = mock_send.call_args[0][0]
            assert sent_request.url.host == "advertising-api-eu.amazon.com"
        set_region_override(None)
    
    async def test_error_handling(self, authenticated_client):
        """Test error handling when auth headers are missing."""
        request = httpx.Request(
            method="GET",
            url="https://advertising-api.amazon.com/test"
        )
        
        # Make auth manager return None to simulate missing headers
        authenticated_client.auth_manager.get_headers = AsyncMock(return_value=None)
        
        with patch.object(httpx.AsyncClient, 'send', new_callable=AsyncMock) as mock_send:
            mock_response = httpx.Response(401, json={"error": "Unauthorized"})
            mock_send.return_value = mock_response
            
            # Missing auth must raise a request error according to client policy
            import pytest
            import httpx as _httpx
            with pytest.raises(_httpx.RequestError):
                await authenticated_client.send(request)
