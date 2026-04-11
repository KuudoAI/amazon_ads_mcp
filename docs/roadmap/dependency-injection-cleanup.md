# Dependency Injection Cleanup

**Priority:** High value, low urgency
**Scope:** `src/amazon_ads_mcp/server/builtin_tools.py`
**Reference:** https://gofastmcp.com/servers/dependency-injection

## Context

Builtin tools currently call singleton factories manually inside their function bodies (`get_auth_manager()`, `get_download_handler()`, `get_http_request()`). FastMCP's dependency injection system (`Depends()`, `CurrentHeaders()`, `CurrentAccessToken()`) can replace these with declarative function parameters that are auto-resolved per request and excluded from the MCP schema.

This is a cleanup refactor — everything works today. DI makes tool signatures clearer and reduces boilerplate.

## What to do

### 1. Replace singleton lookups with `Depends()`

~15 call sites in `builtin_tools.py` manually call `get_auth_manager()` or `get_download_handler()`. Replace with injected dependencies:

```python
from fastmcp.dependencies import Depends

@server.tool(name="get_download_url", ...)
async def get_download_url_tool(
    ctx: Context,
    file_path: str,
    auth_mgr=Depends(get_auth_manager),
    handler=Depends(get_download_handler),
) -> GetDownloadUrlResponse:
    profile_id = auth_mgr.get_active_profile_id()
    ...
```

Per-request caching means each dependency resolves once even if multiple tools or nested dependencies need it.

### 2. Use `CurrentHeaders()` for transport-safe header access

Where tools need HTTP headers with graceful fallback for stdio transport:

```python
from fastmcp.dependencies import CurrentHeaders

@server.tool(...)
async def some_tool(
    ctx: Context,
    headers: dict = CurrentHeaders(),
) -> dict:
    ...
```

### 3. Use `CurrentAccessToken()` / `TokenClaim()` in tools (optional)

For tools that need to read auth identity directly:

```python
from fastmcp.dependencies import CurrentAccessToken
from fastmcp.server.auth import AccessToken

@server.tool(...)
async def some_tool(
    ctx: Context,
    token: AccessToken = CurrentAccessToken(),
):
    identity_id = token.claims.get("identity_id")
```

## What NOT to change

- **Auth middleware** (`src/amazon_ads_mcp/middleware/authentication.py`) — DI does not replace this. The middleware handles refresh-token conversion, JWT validation, and session-state hydration *before* tool execution. `CurrentAccessToken` reads the result; it doesn't create it.
- **Starlette custom routes** (`src/amazon_ads_mcp/server/file_routes.py`) — DI only works in MCP tool/resource/prompt handlers, not in custom HTTP routes.
- **Server construction** (`src/amazon_ads_mcp/server/server_builder.py`) — Build-time setup, not request-time. DI is per-request scope.

## Files affected

| File | Change |
|------|--------|
| `src/amazon_ads_mcp/server/builtin_tools.py` | Replace ~15 manual singleton calls with `Depends()` parameters |
| Tool registration functions | Add dependency parameters to tool signatures |

## Verification

- `uv run ruff check --fix` — lint clean
- `uv run pytest` — all tests pass (DI params are invisible to MCP schema, no client-side changes)
- Verify tools still work via MCP client (`/mcp` in Claude)
