"""FastMCP 2.11 authentication hooks for request authentication.

This module provides request hooks that integrate with FastMCP 2.11's
hook system to automatically add authentication headers to outgoing
HTTP requests, replacing the need for custom HTTP clients.

The module provides:
- AuthHeaderHook: Automatic authentication header injection
- Header pollution cleanup for MCP client compatibility
- Special endpoint handling (e.g., profiles endpoint)
- Response processing for auth-related errors
"""

import logging
from typing import Optional

import httpx
from fastmcp import Context

logger = logging.getLogger(__name__)


class AuthHeaderHook:
    """Request hook that adds authentication headers to outgoing requests.

    This hook integrates with FastMCP 2.11's request lifecycle to automatically
    inject authentication headers into all outgoing HTTP requests. It replaces
    the need for a custom AuthenticatedClient by working with FastMCP's native
    HTTP client.

    The hook provides:
    - Automatic authentication header injection
    - Header pollution cleanup for MCP client compatibility
    - Special endpoint handling (e.g., profiles endpoint)
    - Response processing for auth-related errors

    Example:
        >>> auth_hook = AuthHeaderHook(auth_manager)
        >>> base_mcp.add_request_hook(auth_hook)
    """

    def __init__(self, auth_manager):
        """Initialize the authentication header hook.

        Sets up the hook with the authentication manager that will
        provide the necessary headers for requests.

        :param auth_manager: The authentication manager instance that provides headers
        :type auth_manager: AuthManager
        :return: None
        :rtype: None
        """
        self.auth_manager = auth_manager

    async def before_request(
        self, request: httpx.Request, ctx: Optional[Context] = None
    ) -> httpx.Request:
        """Add authentication headers before the request is sent.

        This method is called by FastMCP before each HTTP request is sent.
        It retrieves the current authentication headers from the auth manager
        and adds them to the request, while also cleaning up any polluted
        headers that might interfere with the Amazon Ads API.

        :param request: The HTTP request to modify
        :type request: httpx.Request
        :param ctx: Optional FastMCP context for the current operation
        :type ctx: Optional[Context]
        :return: The modified request with authentication headers added
        :rtype: httpx.Request
        """
        if not self.auth_manager:
            return request

        try:
            # Get auth headers from manager
            auth_headers = await self.auth_manager.get_headers()
            logger.debug(f"Got auth headers: {list(auth_headers.keys())}")
        except Exception as e:
            logger.error(f"Failed to get auth headers: {e}")
            return request

        # Clean polluted MCP client headers
        # FastMCP sometimes forwards headers from the MCP client that
        # shouldn't go to the Amazon Ads API
        polluted_headers = []
        for key in list(request.headers.keys()):
            key_lower = key.lower()
            if any(
                pattern in key_lower
                for pattern in [
                    "authorization",
                    "clientid",
                    "client-id",
                    "client_id",
                    "amazon-ads",
                    "amazon-advertising",
                    "scope",
                ]
            ):
                polluted_headers.append(key)
                del request.headers[key]

        if polluted_headers:
            logger.debug(
                f"Removed {len(polluted_headers)} polluted headers: {polluted_headers}"
            )

        # Check for special endpoint handling
        url = str(request.url)

        # Handle profiles endpoint special case
        # The /v2/profiles endpoint when listing (no profileId in URL)
        # doesn't accept the Scope header
        if "/v2/profiles" in url and "profileId" not in url:
            auth_headers = auth_headers.copy()
            auth_headers.pop("Amazon-Advertising-API-Scope", None)
            logger.debug("Removed Scope header for profiles listing endpoint")

        # Add auth headers to request
        request.headers.update(auth_headers)

        # Log final headers at DEBUG level only for production safety
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("Final headers being sent to Amazon:")
            for key, value in request.headers.items():
                if "authorization" in key.lower():
                    logger.debug(f"  {key}: {value[:50]}...")
                else:
                    logger.debug(f"  {key}: {value}")

        return request

    async def after_response(
        self, response: httpx.Response, ctx: Optional[Context] = None
    ) -> httpx.Response:
        """Process response after it's received.

        This method can be used to handle auth-related response processing,
        such as detecting expired tokens or rate limits.

        :param response: The HTTP response received
        :type response: httpx.Response
        :param ctx: Optional FastMCP context for the current operation
        :type ctx: Optional[Context]
        :return: The response, potentially modified
        :rtype: httpx.Response
        """
        # Log auth-related errors with more detail
        if response.status_code == 401:
            error_detail = ""
            try:
                error_body = response.json()
                error_detail = f" - Error: {error_body}"
            except:
                error_detail = f" - Response: {response.text[:200]}"

            logger.error(f"Received 401 Unauthorized - token may be expired or invalid{error_detail}")
            logger.error(f"Request URL: {response.request.url}")
            logger.error(f"Request had headers: {list(response.request.headers.keys())}")

            # Check for specific auth headers
            auth_header = response.request.headers.get("authorization", "")
            if not auth_header:
                logger.error("CRITICAL: No Authorization header in request!")
            elif not auth_header.startswith("Bearer "):
                logger.error(f"CRITICAL: Authorization header missing 'Bearer ' prefix: {auth_header[:20]}...")

        elif response.status_code == 403:
            logger.warning("Received 403 Forbidden - check permissions")

        return response
