"""Code Mode integration for Amazon Ads MCP.

Replaces the full tool catalog with meta-tools (discovery + execute) that let
the LLM discover tools on demand and write Python scripts using
``await call_tool(name, params)`` in a sandbox.

Measured token reduction: 98.4% (34,971 -> 547 tokens) across 55 tools.

Configuration is driven by ``Settings`` (env vars ``CODE_MODE``,
``CODE_MODE_INCLUDE_TAGS``, ``CODE_MODE_MAX_DURATION_SECS``,
``CODE_MODE_MAX_MEMORY``).

Integration point: ``ServerBuilder._apply_code_mode()`` calls helpers here.

See also: docs/code-mode.md
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Dict, List

if TYPE_CHECKING:
    from fastmcp import FastMCP

from ..config.settings import settings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Prefix -> human-readable tag mapping
# ---------------------------------------------------------------------------
# Derived from packages.json groups and prefix assignments.
# Multiple prefixes can map to the same tag.
PREFIX_TO_TAG: Dict[str, str] = {
    "cm": "campaign-management",
    "sp": "sponsored-products",
    "spv1": "sponsored-products-v1",
    "sb": "sponsored-brands",
    "sbv1": "sponsored-brands-v1",
    "sd": "sponsored-display",
    "sdv1": "sponsored-display-v1",
    "dsp": "programmatic-dsp",
    "dspv1": "programmatic-dsp-v1",
    "amc": "amazon-marketing-cloud",
    "ac": "accounts",
    "rp": "reporting",
    "br": "brand-insights",
    "st": "stores",
    "stv1": "stores-v1",
    "aud": "audiences",
    "attr": "attribution",
    "ri": "recommendations-insights",
    "creat": "creative-assets",
    "dp": "data-provider",
    "pm": "products-metadata",
    "prod": "products-eligibility",
    "mod": "moderation",
    "ams": "marketing-stream",
    "loc": "locations",
    "export": "exports",
    "mmm": "marketing-mix-modeling",
    "mp": "media-planning",
    "fc": "forecasts",
    "bsm": "brand-stores",
    "test": "test-account",
}

BUILTIN_TAG = "server-management"


def build_discovery_tools() -> list:
    """Build discovery tool instances based on settings.

    Default: ``[GetTags(), Search(), GetSchemas()]`` — the LLM can browse
    categories via tags, search by keyword, then fetch full schemas.

    Set ``CODE_MODE_INCLUDE_TAGS=false`` to drop ``GetTags`` (useful for
    small catalogs where tag browsing adds unnecessary round-trips).

    :return: List of discovery tool instances for CodeMode
    :rtype: list
    :raises ImportError: If ``fastmcp[code-mode]`` extra is not installed
    """
    try:
        from fastmcp.experimental.transforms.code_mode import (
            GetSchemas,
            GetTags,
            Search,
        )
    except ImportError as exc:
        raise ImportError(
            "Code mode requires the 'code-mode' extra. "
            "Install with: pip install 'fastmcp[code-mode]>=3.1.0'"
        ) from exc

    tools: list = []

    if settings.code_mode_include_tags:
        tools.append(GetTags())

    tools.extend([Search(), GetSchemas()])
    return tools


def create_code_mode_transform():
    """Create a configured CodeMode transform instance.

    :return: Configured CodeMode transform
    :raises ImportError: If ``fastmcp[code-mode]`` extra is not installed
        or the ``pydantic_monty`` runtime dependency is missing.
    """
    try:
        from fastmcp.experimental.transforms.code_mode import (
            CodeMode,
            MontySandboxProvider,
        )
    except ImportError as exc:
        raise ImportError(
            "Code mode requires the 'code-mode' extra. "
            "Install with: pip install 'fastmcp[code-mode]>=3.1.0'"
        ) from exc

    # MontySandboxProvider lazy-imports pydantic_monty at .run() time.  Verify
    # it is importable now so we fail loudly at server startup rather than
    # deep inside a tool call like `execute`.
    try:
        import pydantic_monty  # noqa: F401
    except ImportError as exc:
        raise ImportError(
            "Code mode is enabled (CODE_MODE=true) but the Monty sandbox "
            "runtime dependency 'pydantic_monty' is not installed. "
            "Install the code-mode extra with: "
            "pip install 'fastmcp[code-mode]>=3.1.0' "
            "(or set CODE_MODE=false to disable code mode)."
        ) from exc

    sandbox = MontySandboxProvider(
        limits={
            "max_duration_secs": float(settings.code_mode_max_duration_secs),
            "max_memory": settings.code_mode_max_memory,
        }
    )

    discovery_tools = build_discovery_tools()

    transform = CodeMode(
        sandbox_provider=sandbox,
        discovery_tools=discovery_tools,
    )

    logger.info(
        "Created CodeMode transform (timeout=%ds, memory=%dMB, discovery=%d tools, tags=%s)",
        settings.code_mode_max_duration_secs,
        settings.code_mode_max_memory // (1024 * 1024),
        len(discovery_tools),
        settings.code_mode_include_tags,
    )
    return transform


async def tag_tools_by_prefix(
    server: "FastMCP",
    mounted_servers: Dict[str, List["FastMCP"]],
) -> int:
    """Tag all OpenAPI-derived tools by their namespace prefix.

    Uses ``PREFIX_TO_TAG`` mapping for human-readable category names.
    Creates a new ``set`` before assigning to avoid mutating shared references.

    :param server: Main FastMCP server (unused, for API consistency)
    :param mounted_servers: Map of prefix -> list of sub-servers
    :return: Number of tools tagged
    :rtype: int
    """
    tagged = 0
    for prefix, sub_servers in mounted_servers.items():
        tag = PREFIX_TO_TAG.get(prefix, prefix)
        for sub_server in sub_servers:
            tools = await sub_server.list_tools()
            for tool_info in tools:
                try:
                    tool = await sub_server.get_tool(tool_info.name)
                    if tool:
                        # Safe: always create a new set to avoid mutating shared refs
                        tool.tags = {tag} | (tool.tags or set())
                        tagged += 1
                except Exception:
                    pass  # Skip tools that can't be accessed

    logger.info("Tagged %d OpenAPI tools across %d prefixes", tagged, len(mounted_servers))
    return tagged


async def tag_builtin_tools(server: "FastMCP") -> int:
    """Tag all builtin tools with 'server-management'.

    :param server: Main FastMCP server
    :return: Number of tools tagged
    :rtype: int
    """
    tagged = 0
    tools = await server.list_tools()
    for tool_info in tools:
        try:
            tool = await server.get_tool(tool_info.name)
            if tool:
                tool.tags = {BUILTIN_TAG} | (tool.tags or set())
                tagged += 1
        except Exception:
            pass
    logger.info("Tagged %d builtin tools as '%s'", tagged, BUILTIN_TAG)
    return tagged
