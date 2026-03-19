import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


def pytest_configure(config):
    # Register the asyncio marker so pytest doesn't warn when it's used.
    config.addinivalue_line(
        "markers", "asyncio: mark test to run in an asyncio event loop"
    )
    # Add custom markers for test organization
    config.addinivalue_line(
        "markers", "unit: mark test as a unit test"
    )
    config.addinivalue_line(
        "markers", "integration: mark test as an integration test"
    )
    config.addinivalue_line(
        "markers", "auth: mark test as testing authentication"
    )


@pytest.fixture(autouse=True)
def _reset_session_state():
    """Reset per-request ContextVars between tests.

    Prevents auth state from leaking between tests when using
    ContextVar-backed session isolation.
    """
    from amazon_ads_mcp.auth.session_state import reset_session_state

    reset_session_state()
    yield
    reset_session_state()


@pytest.fixture(autouse=True)
def mock_env_vars(monkeypatch):
    """Set required environment variables for tests.

    This fixture automatically sets up the minimum required environment
    variables needed for the Settings class to initialize properly during tests.
    """
    # Authentication configuration
    monkeypatch.setenv("AUTH_METHOD", "direct")
    monkeypatch.setenv("AMAZON_AD_API_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("AMAZON_AD_API_CLIENT_SECRET", "test-client-secret")
    
    # Optional but commonly needed
    monkeypatch.setenv("AMAZON_ADS_REGION", "na")
    monkeypatch.setenv("AMAZON_ADS_SANDBOX_MODE", "false")
    
    # OAuth configuration (for OAuth tests)
    monkeypatch.setenv("OAUTH_REDIRECT_URI", "http://localhost:5173/auth/callback")
    
    # Server configuration
    monkeypatch.setenv("MCP_SERVER_NAME", "amazon-ads-test")
    monkeypatch.setenv("MCP_SERVER_VERSION", "0.1.0-test")
    
    # Logging
    monkeypatch.setenv("LOG_LEVEL", "INFO")
    
    yield


@pytest.fixture
def mock_auth_manager():
    """Mock authentication manager."""
    manager = MagicMock()
    manager.get_headers = AsyncMock(return_value={
        "Authorization": "Bearer test-token",
        "Amazon-Advertising-API-ClientId": "test-client-id",
        "Amazon-Advertising-API-Scope": "test-profile-123"
    })
    manager.get_active_identity = MagicMock(return_value=None)
    manager.get_active_profile_id = MagicMock(return_value="test-profile-123")
    manager.get_active_region = MagicMock(return_value="na")
    return manager


@pytest.fixture
def sample_oauth_token():
    """Sample OAuth token response."""
    return {
        "access_token": "test-access-token",
        "refresh_token": "test-refresh-token",
        "token_type": "bearer",
        "expires_in": 3600,
        "scope": "advertising::campaign_management"
    }


# Rely on pytest-asyncio for async test handling; no custom hook needed.
