"""
Tool naming utilities for MCP servers.

This module provides utilities for managing tool names within the
constraints of the MCP protocol, including name shortening and
prefix management.
"""

import logging
import re
from typing import Dict

logger = logging.getLogger(__name__)

# MCP tool name constraints
MAX_TOOL_NAME = 64
DEFAULT_MAX_PREFIX = 8


def shorten_prefix(namespace: str, max_len: int = DEFAULT_MAX_PREFIX) -> str:
    """
    Shorten a namespace to create a tool prefix.

    Creates an acronym from CamelCase words or truncates the namespace.

    :param namespace: The namespace to shorten
    :type namespace: str
    :param max_len: Maximum length for the prefix
    :type max_len: int
    :return: Shortened prefix string
    :rtype: str
    """
    # Extract capital letters for acronym (e.g., "AccountBudgets" -> "AB")
    parts = re.findall(r"[A-Z][a-z0-9]*", namespace) or [namespace]
    acronym = "".join(p[0] for p in parts if p)

    # Use acronym if available, otherwise truncate namespace
    candidate = (acronym or namespace).lower()[:max_len]

    return candidate or namespace[:max_len].lower()


async def get_tools(server) -> Dict[str, object]:
    """
    Get tools from a FastMCP server.

    Returns a dict keyed by tool name for backward compatibility.
    FastMCP 3.x list_tools() returns a list; we convert to a dict.

    :param server: FastMCP server instance
    :type server: object
    :return: Dictionary of tools keyed by name
    :rtype: Dict[str, object]
    """
    tools_list = await server.list_tools()
    return {t.name: t for t in tools_list}


async def enforce_tool_name_limit(
    server, prefix: str, limit: int = MAX_TOOL_NAME
) -> None:
    """
    Enforce MCP tool name length limits by renaming if necessary.

    MCP has a maximum tool name length. This function renames tools
    that would exceed the limit when combined with their prefix.

    :param server: FastMCP server instance
    :type server: object
    :param prefix: The prefix that will be prepended to tool names
    :type prefix: str
    :param limit: Maximum total name length (default: 64)
    :type limit: int
    :return: None
    :rtype: None
    """
    tools = await get_tools(server)
    rename = getattr(server, "rename_tool", None)

    if not callable(rename):
        logger.info(
            "Tool renaming not supported; prefix '%s', tools=%d",
            prefix,
            len(tools),
        )
        return

    renamed_count = 0

    for local_name in list(tools.keys()):
        # Calculate final name length: prefix + "_" + local_name
        final_len = len(prefix) + 1 + len(local_name)

        if final_len > limit:
            # Calculate how much of the local name we can keep
            keep = max(1, limit - len(prefix) - 1)
            short_local = local_name[:keep]

            if short_local != local_name:
                try:
                    rename(local_name, short_local)
                    renamed_count += 1
                    logger.debug(
                        "Renamed tool '%s' to '%s' (prefix: %s)",
                        local_name,
                        short_local,
                        prefix,
                    )
                except Exception as e:
                    logger.warning("Failed to rename tool '%s': %s", local_name, e)

    if renamed_count > 0:
        logger.info(
            "Renamed %d tools for prefix '%s' to fit %d char limit",
            renamed_count,
            prefix,
            limit,
        )


def validate_tool_name(name: str, prefix: str = "") -> bool:
    """
    Validate that a tool name fits within MCP constraints.

    :param name: The tool name to validate
    :type name: str
    :param prefix: Optional prefix that will be added
    :type prefix: str
    :return: True if the name is valid, False otherwise
    :rtype: bool
    """
    if prefix:
        full_name = f"{prefix}_{name}"
    else:
        full_name = name

    return len(full_name) <= MAX_TOOL_NAME
