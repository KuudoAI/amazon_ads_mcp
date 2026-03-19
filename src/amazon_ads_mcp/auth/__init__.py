"""Authentication module for Amazon Ads MCP.

This module provides authentication management for the Amazon Ads MCP server,
including identity management, token handling, and authentication providers.
Uses a pluggable provider architecture supporting multiple authentication methods.

:var __all__: List of public exports from this module
:type __all__: List[str]
"""

# Import providers to trigger registration
from . import (  # noqa: F401  # imported for side effects (provider registration)
    providers,
)
from .base import (
    BaseAmazonAdsProvider,
    BaseAuthProvider,
    BaseIdentityProvider,
    ProviderConfig,
)
from .manager import AuthManager, get_auth_manager
from .registry import ProviderRegistry, register_provider
from .session_state import reset_session_state

__all__ = [
    "AuthManager",
    "get_auth_manager",
    "ProviderRegistry",
    "register_provider",
    "BaseAuthProvider",
    "BaseIdentityProvider",
    "BaseAmazonAdsProvider",
    "ProviderConfig",
    "reset_session_state",
]
