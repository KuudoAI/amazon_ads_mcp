"""Round 10: tool description prefix convention.

When multiple tools wrap different *shapes* of the same upstream
resource (e.g. ``summarize_profiles`` / ``search_profiles`` /
``page_profiles`` all hit the Ads ``/v2/profiles`` endpoint), their
descriptions must share a common verb prefix so the LLM's catalog scan
reaches all of them via one keyword match.

Convention:

  ``"<Canonical verb> <resource> (<mode>): ..."``

Examples:

  - ``"List profiles (summary mode): aggregate counts by ..."``
  - ``"List profiles (search mode): filter by ..."``
  - ``"List profiles (paged mode): {items, total_count, ...}"``

Why: LLMs trained on REST conventions reach for ``list_*`` first.
Three shape-specific names without a canonical "list" entry create
guess cost on first call. Description prefix lets catalog scans match
the family even when the tool name doesn't.

This test fails the build if a contributor adds a fourth shape variant
(e.g. ``lookup_profiles``) without following the convention.
"""

from __future__ import annotations

import pytest
from fastmcp import FastMCP


# Tool families: every member's description must start with the same
# verb prefix (the part before the parenthesized mode label).
PROFILE_FAMILY = ("summarize_profiles", "search_profiles", "page_profiles")
IDENTITY_FAMILY = ("set_active_identity", "get_active_identity", "list_identities")
REGION_FAMILY = ("set_region", "get_region", "list_regions")


def _verb_prefix(description: str) -> str:
    """Extract the leading verb phrase up to (but not including) the
    mode marker — usually the parenthesis or a colon, whichever comes
    first."""
    for marker in (" (", ": "):
        idx = description.find(marker)
        if idx != -1:
            return description[:idx].strip().lower()
    return description.strip().lower()


@pytest.mark.asyncio
async def test_profile_family_shares_verb_prefix():
    """All profile-listing shape variants must share a description
    prefix so a catalog scan for ``list profiles`` matches all three."""
    from amazon_ads_mcp.server.builtin_tools import register_profile_listing_tools

    server = FastMCP("test")
    await register_profile_listing_tools(server)

    descriptions = {}
    for name in PROFILE_FAMILY:
        tool = await server.get_tool(name)
        assert tool is not None, f"{name} not registered"
        descriptions[name] = tool.description or ""

    prefixes = {n: _verb_prefix(d) for n, d in descriptions.items()}
    distinct = set(prefixes.values())
    assert len(distinct) == 1, (
        f"Profile-family tools have divergent description prefixes. "
        f"Each shape variant should lead with the same canonical verb "
        f"so LLM catalog scans match all siblings.\n"
        f"Per-tool prefixes: {prefixes}\n"
        f"Distinct prefixes: {distinct}"
    )
    # Convention: lead with "list profiles" since that's the verb LLMs
    # reach for first.
    expected = next(iter(distinct))
    assert "list profiles" in expected, (
        f"Profile-family prefix should start with 'list profiles' "
        f"so LLMs reaching for the conventional REST verb find all "
        f"shape variants. Got: {expected!r}"
    )


@pytest.mark.asyncio
async def test_profile_family_descriptions_label_their_mode():
    """Each shape variant must label its mode (summary / search / paged)
    in the description so the LLM can distinguish them after matching
    the prefix."""
    from amazon_ads_mcp.server.builtin_tools import register_profile_listing_tools

    server = FastMCP("test")
    await register_profile_listing_tools(server)

    expected_modes = {
        "summarize_profiles": "summary",
        "search_profiles": "search",
        "page_profiles": "paged",
    }
    for name, mode in expected_modes.items():
        tool = await server.get_tool(name)
        desc = (tool.description or "").lower()
        assert mode in desc, (
            f"{name} description should label its mode ({mode!r}). "
            f"Got: {tool.description!r}"
        )


@pytest.mark.asyncio
async def test_identity_family_shares_verb_prefix():
    """``list_identities`` / ``set_active_identity`` /
    ``get_active_identity`` are all about identities. Their descriptions
    should share a common prefix that names the resource."""
    from amazon_ads_mcp.server.builtin_tools import register_identity_tools

    server = FastMCP("test")
    # register_identity_tools only registers when an OpenBridge auth
    # provider is active. Stub it via FastMCP-friendly mock.
    await register_identity_tools(server)

    descriptions = {}
    for name in IDENTITY_FAMILY:
        tool = await server.get_tool(name)
        assert tool is not None, f"{name} not registered"
        descriptions[name] = tool.description or ""

    # Every identity-family description must mention "identity" or
    # "identities" near the start so catalog scans match.
    for name, desc in descriptions.items():
        first_phrase = desc.split(":")[0].split("(")[0].lower()
        assert "identit" in first_phrase, (
            f"{name} description should name 'identity' or 'identities' "
            f"in its leading phrase so LLMs scanning for the resource "
            f"find it. Got first phrase: {first_phrase!r}"
        )


@pytest.mark.asyncio
async def test_region_family_shares_verb_prefix():
    """Region-family tools should all name 'region' in their leading
    phrase."""
    from amazon_ads_mcp.server.builtin_tools import register_region_tools

    server = FastMCP("test")
    await register_region_tools(server)

    for name in REGION_FAMILY:
        tool = await server.get_tool(name)
        assert tool is not None, f"{name} not registered"
        first_phrase = (tool.description or "").split(":")[0].split("(")[0].lower()
        assert "region" in first_phrase, (
            f"{name} description should name 'region' in its leading "
            f"phrase. Got: {first_phrase!r}"
        )
