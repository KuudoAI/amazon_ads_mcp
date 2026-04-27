"""Unit tests for AuthenticatedClient.

Tests the header scrubbing, injection, and media type negotiation
functionality of the AuthenticatedClient.
"""

import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch
import httpx
import respx

from amazon_ads_mcp.utils.http_client import AuthenticatedClient
from amazon_ads_mcp.utils.header_resolver import HeaderNameResolver
from amazon_ads_mcp.utils.media import MediaTypeRegistry

from tests.conftest import make_direct_auth_manager


@pytest.fixture
def mock_auth_manager():
    """Spec'd direct-provider AuthManager from the shared factory.

    Headers tweaked from the factory default to include this file's
    historical Scope value (``test-profile-id``).
    """
    return make_direct_auth_manager(headers={
        "Authorization": "Bearer test-token",
        "Amazon-Advertising-API-ClientId": "test-client-id",
        "Amazon-Advertising-API-Scope": "test-profile-id",
    })


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
        
        # respx intercepts at the transport layer — sees the wire request
        # exactly as httpx serializes it, including the case-folded header
        # forms produced by httpx's own normalization.
        with respx.mock(assert_all_called=True) as respx_mock:
            route = respx_mock.get(
                "https://advertising-api.amazon.com/test"
            ).mock(return_value=httpx.Response(200, json={"success": True}))

            await authenticated_client.send(request)

            sent_request = route.calls.last.request

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
        
        with respx.mock(assert_all_called=True) as respx_mock:
            route = respx_mock.post(
                "https://advertising-api.amazon.com/campaigns"
            ).mock(return_value=httpx.Response(200, json={"id": "123"}))

            await authenticated_client.send(request)

            sent_request = route.calls.last.request

        # Verify auth manager was called
        mock_auth_manager.get_headers.assert_called_once()
        # Verify headers were injected on the wire
        assert sent_request.headers.get("authorization") == "Bearer test-token"
        assert sent_request.headers.get("Amazon-Advertising-API-ClientId") is not None
    
    async def test_headers_reinjected_on_every_send(self, authenticated_client):
        """Headers must be (re-)injected on every ``send`` so retry attempts
        pick up refreshed tokens. The legacy ``auth_injected`` short-circuit
        broke refresh-during-retry and has been removed."""
        request = httpx.Request(
            method="GET",
            url="https://advertising-api.amazon.com/test"
        )

        with patch.object(authenticated_client, '_inject_headers', autospec=True) as mock_inject:
            with patch.object(httpx.AsyncClient, 'send', autospec=True) as mock_send:
                mock_send.return_value = httpx.Response(200)
                await authenticated_client.send(request)
                await authenticated_client.send(request)

                assert mock_inject.await_count == 2
    
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
        
        with respx.mock(assert_all_called=True) as respx_mock:
            route = respx_mock.get(
                "https://advertising-api.amazon.com/reports/12345/download"
            ).mock(return_value=httpx.Response(200))

            await authenticated_client.send(request)

            sent_request = route.calls.last.request

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
        try:
            # The region override rewrites the URL host before send().
            # respx must be set up on the EU host (where the request
            # actually goes), not the original NA host. If the rewrite
            # ever stops working, respx returns "no matching route" rather
            # than silently letting NA pass through.
            with respx.mock(assert_all_called=True) as respx_mock:
                route = respx_mock.get(
                    "https://advertising-api-eu.amazon.com/profiles"
                ).mock(return_value=httpx.Response(200, json=[]))

                await authenticated_client.send(request)

                sent_request = route.calls.last.request

            assert sent_request.url.host == "advertising-api-eu.amazon.com"
        finally:
            set_region_override(None)
    
    async def test_error_handling(self, authenticated_client):
        """Missing auth headers must raise BEFORE reaching the wire.

        The client policy refuses to send a request without auth headers,
        so we don't need a transport mock — if the assertion fires, send()
        was never called. Using ``respx.mock(assert_all_called=False)`` to
        document that no upstream call should happen on this path.
        """
        request = httpx.Request(
            method="GET",
            url="https://advertising-api.amazon.com/test"
        )

        # Make auth manager return None to simulate missing headers
        authenticated_client.auth_manager.get_headers = AsyncMock(return_value=None)

        with respx.mock(assert_all_called=False) as respx_mock:
            # Set up a route that should NEVER fire on this code path.
            # If the policy regresses and a request slips through without
            # auth, this route catches it (call_count == 1) and the
            # follow-up assertion in the test exposes the regression.
            route = respx_mock.get(
                "https://advertising-api.amazon.com/test"
            ).mock(return_value=httpx.Response(401))

            with pytest.raises(httpx.RequestError):
                await authenticated_client.send(request)

            # Critical: no wire request should have happened.
            assert route.call_count == 0, (
                "AuthenticatedClient sent a request despite missing auth "
                "headers — policy regression."
            )
