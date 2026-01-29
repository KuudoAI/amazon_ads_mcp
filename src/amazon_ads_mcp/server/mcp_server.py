#!/usr/bin/env python3
"""Amazon Ads MCP Server - Modular Implementation.

This is a refactored version of the MCP server that uses modular components
for better maintainability and testability.

Implements the FastMCP server lifespan pattern for clean startup/shutdown.
"""

import argparse
import asyncio
import atexit
import logging
import os
import signal
import sys
import types
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any, Optional

# Note: FASTMCP_EXPERIMENTAL_ENABLE_NEW_OPENAPI_PARSER removed in v0.1.18
# The new OpenAPI parser is now standard in FastMCP 2.14.0+
# See: https://gofastmcp.com/v2/development/upgrade-guide

from ..utils.http import http_client_manager
from ..utils.security import setup_secure_logging
from .server_builder import ServerBuilder

logger = logging.getLogger(__name__)


@asynccontextmanager
async def server_lifespan(server: Any) -> AsyncIterator[None]:
    """Server lifespan context manager for clean startup and shutdown.

    This lifespan function handles all server initialization and cleanup
    in a single, testable async context manager. It's passed to the FastMCP
    constructor to ensure proper resource management.

    FastMCP 2.14+ passes the server instance to lifespan functions, which
    enables access to server state during startup/shutdown.

    Startup:
        - Validates authentication configuration
        - Initializes HTTP client connections
        - Logs server state

    Shutdown:
        - Closes all HTTP client connections
        - Shuts down the authentication manager
        - Performs graceful cleanup

    Usage:
        server = FastMCP("Server", lifespan=server_lifespan)

    :param server: The FastMCP server instance (provided by FastMCP)
    :yield: Control to the running server
    :rtype: AsyncIterator[None]
    """
    _ = server  # Server instance available if needed for future enhancements
    logger.info("Server lifespan: Starting up...")

    # Startup phase
    try:
        # Log initial state
        from ..auth.manager import get_auth_manager

        auth_mgr = get_auth_manager()
        if auth_mgr and auth_mgr.provider:
            provider_type = getattr(auth_mgr.provider, "provider_type", "unknown")
            logger.info(f"Auth provider initialized: {provider_type}")
        else:
            logger.warning("No auth provider configured")

        logger.info("Server lifespan: Startup complete")
    except Exception as e:
        logger.error(f"Server lifespan: Startup error: {e}")
        raise

    try:
        # Yield control to the running server
        yield
    finally:
        # Shutdown phase - coordinate with fallback cleanup handlers
        global _cleanup_done

        if _cleanup_done:
            logger.debug("Server lifespan: Cleanup already done by fallback handler")
            return

        logger.info("Server lifespan: Shutting down...")

        # Close HTTP clients
        try:
            await http_client_manager.close_all()
            logger.info("HTTP clients closed")
        except Exception as e:
            logger.error(f"Error closing HTTP clients: {e}")

        # Close auth manager
        try:
            from ..auth.manager import get_auth_manager

            am = get_auth_manager()
            if am:
                await am.close()
                logger.info("Auth manager closed")
        except Exception as e:
            logger.error(f"Error closing auth manager: {e}")

        # Mark cleanup done to prevent fallback handlers from running again
        _cleanup_done = True
        logger.info("Server lifespan: Shutdown complete")


async def create_amazon_ads_server() -> Any:
    """Create and configure the Amazon Ads MCP server using modular components.

    This function creates a new Amazon Ads MCP server instance using the
    modular ServerBuilder. The server is fully configured with builtin tools,
    authentication middleware, and lifespan management.

    The lifespan pattern (FastMCP 2.14+) handles:
    - Clean startup with auth validation
    - Graceful shutdown with resource cleanup
    - HTTP client connection management
    - Auth manager lifecycle

    :return: Configured FastMCP server instance
    :raises Exception: If server initialization fails

    Examples
    --------
    .. code-block:: python

        server = await create_amazon_ads_server()
        await server.run()
    """
    # Pass the lifespan to the builder for clean startup/shutdown
    builder = ServerBuilder(lifespan=server_lifespan)
    server = await builder.build()

    # Built-in tools are registered in ServerBuilder._setup_builtin_tools()
    # FastMCP handles prompts automatically

    logger.info("MCP server setup complete (lifespan pattern enabled)")
    return server


_cleanup_task = None
_cleanup_done = False


async def cleanup_resources_async() -> None:
    """Perform async cleanup of server resources.

    This function performs asynchronous cleanup of server resources including
    HTTP client connections and authentication manager shutdown. It ensures
    that cleanup is only performed once and handles errors gracefully.

    :raises Exception: If cleanup operations fail
    """
    global _cleanup_done
    if _cleanup_done:
        return

    logger.info("Shutting down server...")
    try:
        await http_client_manager.close_all()
        logger.info("HTTP clients closed")
    except Exception as e:
        logger.error("Error closing http clients: %s", e)

    try:
        from ..auth.manager import get_auth_manager

        am = get_auth_manager()
        if am:
            await am.close()
            logger.info("Auth manager closed")
    except Exception as e:
        logger.error("Error closing auth manager: %s", e)

    _cleanup_done = True


def cleanup_sync() -> None:
    """Synchronously clean up server resources.

    This function performs cleanup operations for the server in a safe manner
    that avoids creating new event loops in signal handlers.

    The cleanup includes:
    - Closing all HTTP client connections
    - Shutting down the authentication manager
    - Handling any cleanup errors gracefully
    """
    global _cleanup_task, _cleanup_done

    if _cleanup_done:
        return

    # Try to schedule cleanup in existing event loop
    try:
        loop = asyncio.get_running_loop()
        if not loop.is_closed() and not _cleanup_task:
            _cleanup_task = loop.create_task(cleanup_resources_async())
            logger.debug("Cleanup scheduled in running event loop")
            return
    except RuntimeError:
        # No running loop - that's OK for signal handlers
        pass

    # For atexit (not signal handlers), we can try more thorough cleanup
    frame: Optional[types.FrameType] = sys._getframe()
    # Check if we're in a signal handler by inspecting the stack
    in_signal = False
    while frame:
        if frame.f_code.co_name in (
            "<module>",
            "<lambda>",
        ) and "signal" in str(frame.f_code.co_filename):
            in_signal = True
            break
        frame = frame.f_back

    if not in_signal and not _cleanup_done:
        # Safe to create new event loop when not in signal handler
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(cleanup_resources_async())
            loop.close()
            logger.info("Cleanup complete via new event loop")
        except Exception as e:
            logger.debug(f"Could not perform sync cleanup: {e}")


def main() -> None:
    """Run the Amazon Ads MCP server.

    This is the main entry point for the Amazon Ads MCP server. It parses
    command line arguments, initializes logging, creates the server, and
    starts it with the specified transport.

    The function supports multiple transport modes:
    - stdio: Standard input/output communication
    - http: HTTP-based communication
    - streamable-http: Server-sent events HTTP communication

    :raises KeyboardInterrupt: If the server is stopped by user interrupt
    :raises Exception: If server initialization or startup fails

    Examples
    --------
    .. code-block:: bash

        # Run with HTTP transport
        python -m amazon_ads_mcp.server.mcp_server --transport http --port 9080

        # Run with stdio transport
        python -m amazon_ads_mcp.server.mcp_server --transport stdio
    """
    # Load environment variables from .env file if it exists
    try:
        from dotenv import load_dotenv

        load_dotenv()
    except ImportError:
        pass

    setup_secure_logging(level=os.environ.get("LOG_LEVEL", "INFO"))
    logger.debug("Environment variables loaded")

    parser = argparse.ArgumentParser(description="Amazon Ads MCP Server (Modular)")
    parser.add_argument(
        "--transport",
        choices=["stdio", "http", "streamable-http"],
        default="stdio",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9080)
    args = parser.parse_args()

    # Set the port in environment for OAuth redirect URI
    if args.transport in ("http", "streamable-http"):
        os.environ["PORT"] = str(args.port)

    # Register cleanup handlers
    atexit.register(cleanup_sync)
    signal.signal(signal.SIGTERM, lambda *_: cleanup_sync())
    signal.signal(signal.SIGINT, lambda *_: cleanup_sync())

    logger.info("Creating Amazon Ads MCP server...")
    mcp = asyncio.run(create_amazon_ads_server())

    # Small delay to ensure server is fully initialized
    import time

    time.sleep(0.5)
    logger.info("Server initialization complete")

    try:
        if args.transport in ("http", "streamable-http"):
            transport = (
                "streamable-http" if args.transport == "streamable-http" else "http"
            )
            logger.info("Starting %s server on %s:%d", transport, args.host, args.port)
            # Use streamable-http transport which handles SSE properly
            mcp.run(
                transport=transport,
                host=args.host,
                port=args.port,
                # Using default path to avoid redirect issues
            )
        else:
            logger.info("Running in stdio mode")
            mcp.run()
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    finally:
        cleanup_sync()


if __name__ == "__main__":
    main()
