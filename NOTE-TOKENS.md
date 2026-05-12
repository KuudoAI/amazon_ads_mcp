# Token Sources

This repo uses two refresh-token sources, one per brand. Two MCP server entries
in `~/.claude.json` (`amazon-ads` for PBN, `amazon-ads-sh` for SH) load them
side-by-side so both brands are reachable in the same Claude Code session.

## ~/.claude.json `amazon-ads` entry → PBN
- Refresh token for Photo Booth Nook.
- Default profile: 3987763286122956 (PBN US seller).
- Also covers PBN CA seller (profile 2560467967906921) — same token, just switch
  active_profile.
- Tools surface as `mcp__amazon-ads__*`.

## ~/.claude.json `amazon-ads-sh` entry → SH
- Refresh token for Sap Happy Sugarin' Supplies.
- Default profile: 3778622964304303 (SH US seller).
- Also covers SH CA (1018256446748374) and SH MX (351892444800497) — same
  token, just switch active_profile.
- Tools surface as `mcp__amazon-ads-sh__*`.

### CRITICAL GOTCHA — "Rusty Dog Outdoors" label is SH

When you call `/v2/profiles` with the SH token, every profile comes back with
`accountInfo.name = 'Rusty Dog Outdoors'`. That's the original account name
Craig set when creating the SH Seller Central account; Amazon will not let him
rename it. **It is still SH.** Do not let the `accountInfo.name` mislead you
into thinking these are RDO profiles — RDO is a separate brand that does not
have its own Amazon Ads presence.

## .env at project root
- Originally held the SH refresh token under the misleading "RDO" framing.
- Now redundant: `~/.claude.json` `amazon-ads-sh` entry is the source of truth.
- Kept on disk as a backup; do not load from helper scripts. Use the MCP tools
  instead, namespaced by brand.

## Pattern to follow
- **Default to MCP tool calls** for all Amazon Ads API access. The MCP handles
  token sourcing, region routing, and endpoint shape correctly.
- For PBN work, use `mcp__amazon-ads__*` tools. For SH work, use
  `mcp__amazon-ads-sh__*` tools. Pick the right server before acting — the
  namespacing prevents cross-brand mistakes.
- Avoid raw httpx in helper scripts — past bugs (SP v3 expression-type case
  mismatch, GET /v2/portfolios endpoint shape) lived in helper scripts that
  bypassed the MCP. See `src/amazon_ads_mcp/utils/sp_enum_normalize.py` (commit
  2b506a2) for the SP v3 normalization helper that should be imported by any
  script that does need to parse response types.

## Pattern to follow
- **Default to MCP tool calls** for all Amazon Ads API access. The MCP handles token sourcing and endpoint shape correctly.
- Avoid raw httpx in helper scripts — past bugs (SP v3 expression-type case mismatch, GET /v2/portfolios endpoint shape) lived in helper scripts that bypassed the MCP. See `src/amazon_ads_mcp/utils/sp_enum_normalize.py` (commit 2b506a2) for the SP v3 normalization helper that should be imported by any script that does need to parse response types.

---
*Created 2026-05-05 during a Marketing weekly review session that surfaced the token-source split. Source: Rusty Dog Brands Cowork PPC pipeline.*
