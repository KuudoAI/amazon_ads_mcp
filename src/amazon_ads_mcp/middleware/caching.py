"""Response caching middleware for Amazon Ads MCP.

This module provides a security-aware caching configuration that prevents
cross-account data leakage in multi-tenant scenarios.

Security Considerations
-----------------------
Amazon Ads MCP operates in a multi-tenant context where:
- Different profiles have different data access
- Region affects API endpoints and responses
- Account ID determines data isolation

The default FastMCP cache key (method + arguments) is UNSAFE because:
- Profile context is implicit (via Amazon-Advertising-API-Scope header)
- Results vary by active profile, but cache key doesn't include it
- OpenBridge identities add another dimension of isolation

Safe Caching Strategy
---------------------
1. WHITELIST ONLY - explicit list of safe-to-cache tools
2. STATIC DATA ONLY - tools that return the same data regardless of context
3. NO API CALLS - only cache server-local metadata

Examples
--------
.. code-block:: python

    from amazon_ads_mcp.middleware.caching import create_caching_middleware

    middleware = create_caching_middleware()
    server.add_middleware(middleware)
"""

import logging
from typing import Optional, Set

from fastmcp.server.middleware.caching import (
    CallToolSettings,
    ListPromptsSettings,
    ListResourcesSettings,
    ListToolsSettings,
    ResponseCachingMiddleware,
)

logger = logging.getLogger(__name__)


# Tools that are SAFE to cache (static data, no profile dependency)
SAFE_TO_CACHE_TOOLS: Set[str] = {
    # Region configuration - static server data
    "list_regions",
    # Downloads - local filesystem, not API-dependent
    "list_downloads",
}

# Tools that MUST NOT be cached (profile-dependent, write operations, or dynamic)
# This is a documentation list - actual enforcement is via whitelist above
NEVER_CACHE_TOOLS: Set[str] = {
    # Profile/Identity management - state changes
    "set_active_profile",
    "get_active_profile",  # Depends on server state
    "clear_active_profile",
    "set_active_identity",
    "get_active_identity",  # Depends on server state
    "list_identities",  # Depends on auth provider
    # Region management - state changes
    "set_region",
    "get_region",  # Depends on server state
    "get_routing_state",  # Depends on current routing config
    # OAuth operations - security sensitive
    "start_oauth_flow",
    "check_oauth_status",
    "refresh_oauth_token",
    "clear_oauth_tokens",
    # Download operations - side effects
    "download_export",
    # Sampling - dynamic operations
    "test_sampling",
    # ALL OpenAPI-generated tools - profile-dependent API responses
    # These are excluded by whitelist (not in SAFE_TO_CACHE_TOOLS)
}

# TTL values in seconds
STATIC_DATA_TTL = 3600  # 1 hour for truly static data
LIST_METADATA_TTL = 60  # 1 minute for tool/resource/prompt lists


def create_caching_middleware(
    enabled: bool = True,
    static_ttl: int = STATIC_DATA_TTL,
    list_ttl: int = LIST_METADATA_TTL,
    additional_safe_tools: Optional[Set[str]] = None,
) -> ResponseCachingMiddleware:
    """Create a security-aware caching middleware.

    This middleware implements a conservative whitelist approach:
    - Only explicitly listed tools are cached
    - All OpenAPI-generated tools are excluded (profile-dependent)
    - Write operations are never cached

    :param enabled: Whether caching is enabled globally
    :param static_ttl: TTL for static data (e.g., list_regions)
    :param list_ttl: TTL for list operations (tools, resources, prompts)
    :param additional_safe_tools: Additional tool names safe to cache
    :return: Configured ResponseCachingMiddleware

    Example
    -------
    .. code-block:: python

        middleware = create_caching_middleware(
            static_ttl=1800,  # 30 minutes
            additional_safe_tools={"my_static_tool"}
        )
        server.add_middleware(middleware)
    """
    safe_tools = SAFE_TO_CACHE_TOOLS.copy()
    if additional_safe_tools:
        safe_tools.update(additional_safe_tools)

    logger.info(
        f"Creating caching middleware with {len(safe_tools)} safe tools: {safe_tools}"
    )

    return ResponseCachingMiddleware(
        # Tool call caching - WHITELIST ONLY
        call_tool_settings=CallToolSettings(
            enabled=enabled,
            ttl=static_ttl,
            included_tools=list(safe_tools),  # Only these tools are cached
        ),
        # List operations - safe to cache (server metadata)
        list_tools_settings=ListToolsSettings(
            enabled=enabled,
            ttl=list_ttl,
        ),
        list_resources_settings=ListResourcesSettings(
            enabled=enabled,
            ttl=list_ttl,
        ),
        list_prompts_settings=ListPromptsSettings(
            enabled=enabled,
            ttl=list_ttl,
        ),
        # Resource reads - DISABLED (may be profile-dependent)
        # read_resource_settings=ReadResourceSettings(enabled=False),
        # Prompt gets - DISABLED (may be profile-dependent)
        # get_prompt_settings=GetPromptSettings(enabled=False),
    )


# Future enhancement: Custom cache key middleware
# This would allow caching OpenAPI tools safely by including
# profile_id/region/account_id in the cache key
#
# class ContextAwareCacheKeyMiddleware(Middleware):
#     """Middleware that injects routing context into cache keys.
#
#     This middleware captures the current profile_id, region, and
#     account_id and stores them in context state for use by a
#     custom caching implementation.
#     """
#
#     async def on_call_tool(self, context: MiddlewareContext, call_next):
#         # Get current routing context
#         from ..utils.http_client import get_routing_state
#         routing = get_routing_state()
#
#         # Store in context for cache key generation
#         if context.fastmcp_context:
#             context.fastmcp_context.set_state("cache_context", {
#                 "region": routing.get("region"),
#                 "profile_id": routing.get("profile_id"),
#                 "account_id": routing.get("account_id"),
#             })
#
#         return await call_next(context)
