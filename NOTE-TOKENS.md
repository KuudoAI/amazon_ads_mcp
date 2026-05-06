# Token Sources

This repo uses two refresh-token sources. Knowing which is active matters.

## ~/.claude.json (runtime — DEFAULT for the MCP server)
- Active profile for Marketing / PPC work: PBN (Photo Booth Nook), profile_id 3987763286122956.
- The MCP server loads from this file at startup.
- All MCP tool calls (campaign reads, negative-keyword updates, etc.) use this token.

## .env at project root (RDO testing context — secondary)
- Refresh token for Rusty Dog Outdoors (3 profiles, none of which is PBN).
- Purpose unclear (Craig has not touched this file). Possibly stale, possibly intentional for RDO-specific testing.
- **Helper scripts that need PBN access must NOT load this .env.** Helper scripts should either rely on the MCP runtime token (preferred — call the MCP tools instead of raw API) or explicitly load from ~/.claude.json.

## Pattern to follow
- **Default to MCP tool calls** for all Amazon Ads API access. The MCP handles token sourcing and endpoint shape correctly.
- Avoid raw httpx in helper scripts — past bugs (SP v3 expression-type case mismatch, GET /v2/portfolios endpoint shape) lived in helper scripts that bypassed the MCP. See `src/amazon_ads_mcp/utils/sp_enum_normalize.py` (commit 2b506a2) for the SP v3 normalization helper that should be imported by any script that does need to parse response types.

---
*Created 2026-05-05 during a Marketing weekly review session that surfaced the token-source split. Source: Rusty Dog Brands Cowork PPC pipeline.*
