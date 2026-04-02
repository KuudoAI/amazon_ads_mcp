# Test Plan: Authorization Header Propagation (OpenBridge)

**Version**: 0.3.0 (feat-mcp-apps branch)
**Date**: 2026-04-02
**Image**: `openbridgeops/amazon-ads-mcp:latest`

---

## Background

The Amazon Ads MCP server supports multi-tenant authentication via OpenBridge. Clients pass their OpenBridge refresh token in the `Authorization: Bearer <token>` HTTP header. The server middleware extracts this token and passes it to the OpenBridge provider, which converts it to a JWT for Amazon Ads API calls.

A critical bug was found where the `Authorization` header was silently dropped on `streamable-http` transports because the middleware read headers from `request_context` (which is `None` before the MCP session is established). The fix adds a fallback to `get_http_request()` from FastMCP's dependency injection.

---

## Prerequisites

### Server Environment Variables (Required)

```bash
AMAZON_ADS_AUTH_METHOD=openbridge
TRANSPORT=streamable-http   # or http
HOST=0.0.0.0
PORT=9080
CODE_MODE=true              # default; set to false to expose tools directly
```

Setting `AMAZON_ADS_AUTH_METHOD=openbridge` automatically enables refresh token middleware and auth processing. No additional auth toggles needed.

**Do NOT set** `OPENBRIDGE_REFRESH_TOKEN`, `OPENBRIDGE_API_KEY`, or any server-side credentials. The entire point is that credentials come from the client.

### Client Requirements

- An OpenBridge refresh token (format: `<id>:<secret>`, e.g. `CVi5Dvh00FHxqXJp3YJhi0:462ae292bfeb4731a3bce839cdb750fe`)
- The OpenBridge account must have at least one Amazon Ads remote identity (type 14) configured
- Python 3.10+ with `fastmcp>=3.2.0` installed, OR `npx mcp-remote@latest`

---

## Test 1: Local Docker Smoke Test

### Setup

```bash
# Build and run locally
docker-compose up -d --build

# Verify server starts cleanly
docker logs amazon-ads-mcp 2>&1 | grep -E "ERROR|WARNING|Registered"
```

**Expected startup logs** (no errors):
```
Added RefreshTokenMiddleware
Created 1 middleware components
Added 1 OpenBridge authentication middleware components
Registered OAuth callback route at /auth/callback
MCP server setup complete
```

**Failure indicators**:
- Missing "Added RefreshTokenMiddleware" → `REFRESH_TOKEN_ENABLED` not set
- "No OpenBridge token available" at startup → Server trying to use provider before client connects (acceptable, will resolve on first request)

### Run

```bash
# Health check
curl -s http://localhost:9080/health
# Expected: {"status":"ok"}

# MCP endpoint exists
curl -s -o /dev/null -w "%{http_code}" http://localhost:9080/mcp
# Expected: 400 (no MCP session headers, but not 404)
```

---

## Test 2: Token Propagation via Python Client

This is the critical test. It verifies the Bearer token reaches the OpenBridge provider.

### Script: `test_token_propagation.py`

```python
"""Verify Bearer token propagation to OpenBridge provider."""
import asyncio
import json
import sys
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport

SERVER_URL = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:9080/mcp"
TOKEN = sys.argv[2] if len(sys.argv) > 2 else None

if not TOKEN:
    print("Usage: python test_token_propagation.py <server_url> <openbridge_token>")
    print("Example: python test_token_propagation.py http://localhost:9080/mcp 'CVi5Dvh00FHxqXJp3YJhi0:secret'")
    sys.exit(1)

async def main():
    transport = StreamableHttpTransport(
        SERVER_URL,
        headers={
            "Authorization": f"Bearer {TOKEN}",
            "Accept": "application/json, text/event-stream",
        },
    )

    async with Client(transport) as client:
        # Test 2a: List tools (should succeed regardless of auth)
        tools = await client.list_tools()
        tool_names = [t.name for t in tools]
        print(f"[PASS] Connected. {len(tool_names)} tools available.")

        # Test 2b: Call list_identities directly
        # (works even with CODE_MODE=true, tools are callable by name)
        print("\nCalling list_identities...")
        try:
            result = await client.call_tool("list_identities", {})
            if result.is_error:
                print(f"[FAIL] list_identities returned error")
                for item in (result.content or []):
                    print(f"  {getattr(item, 'text', str(item))}")
                return False

            # Parse response
            has_identities = False
            for item in (result.content or []):
                text = getattr(item, 'text', None)
                if text:
                    try:
                        data = json.loads(text)
                        identities = data.get("identities", [])
                        total = data.get("total", 0)
                        print(f"[PASS] list_identities returned {total} identities:")
                        for ident in identities:
                            attrs = ident.get("attributes", {})
                            print(f"  - ID {ident['id']}: {attrs.get('name')} ({attrs.get('email')}) region={attrs.get('region')}")
                        has_identities = total > 0
                    except json.JSONDecodeError:
                        print(f"  Raw: {text[:500]}")

            if not has_identities:
                print("[FAIL] No identities returned. Check:")
                print("  1. Is the OpenBridge token valid?")
                print("  2. Does the account have Amazon Ads identities (type 14)?")
                print("  3. Check server logs for middleware/auth errors")
                return False

        except Exception as e:
            error_msg = str(e)
            if "No OpenBridge token available" in error_msg:
                print(f"[FAIL] Token NOT propagated to provider!")
                print(f"  The Authorization header was not extracted by middleware.")
                print(f"  Check: REFRESH_TOKEN_ENABLED=true, AUTH_ENABLED=true")
                print(f"  Check: Server image has get_http_request() fallback in middleware")
            else:
                print(f"[FAIL] {type(e).__name__}: {e}")
            return False

        # Test 2c: Set active identity and verify
        print("\nSetting active identity...")
        try:
            # Use the first identity
            result = await client.call_tool("list_identities", {})
            first_id = None
            for item in (result.content or []):
                text = getattr(item, 'text', None)
                if text:
                    data = json.loads(text)
                    identities = data.get("identities", [])
                    if identities:
                        first_id = identities[0]["id"]

            if first_id:
                result = await client.call_tool("set_active_identity", {"identity_id": first_id})
                print(f"[PASS] Set active identity to {first_id}")

                # Verify it stuck
                result = await client.call_tool("get_active_identity", {})
                for item in (result.content or []):
                    text = getattr(item, 'text', None)
                    if text:
                        data = json.loads(text)
                        active_id = data.get("identity_id") or data.get("id")
                        if str(active_id) == str(first_id):
                            print(f"[PASS] get_active_identity confirms {active_id}")
                        else:
                            print(f"[WARN] Active identity mismatch: expected {first_id}, got {active_id}")
        except Exception as e:
            print(f"[FAIL] set_active_identity: {e}")
            return False

        # Test 2d: Summarize profiles (requires active identity + valid auth)
        print("\nCalling summarize_profiles...")
        try:
            result = await client.call_tool("summarize_profiles", {})
            if result.is_error:
                for item in (result.content or []):
                    text = getattr(item, 'text', str(item))
                    if "No active identity" in text:
                        print(f"[FAIL] Identity not persisted across calls")
                    elif "Authentication required" in text:
                        print(f"[FAIL] Token propagation broken for API calls")
                        print(f"  The token reached list_identities but not the HTTP client.")
                    else:
                        print(f"[FAIL] {text[:500]}")
                return False
            else:
                for item in (result.content or []):
                    text = getattr(item, 'text', None)
                    if text:
                        data = json.loads(text)
                        total = data.get("total_profiles", 0)
                        print(f"[PASS] summarize_profiles: {total} profiles found")
                        for country, count in data.get("by_country", {}).items():
                            print(f"  {country}: {count} profiles")
        except Exception as e:
            print(f"[FAIL] summarize_profiles: {e}")
            return False

        print("\n[ALL PASS] Token propagation verified end-to-end.")
        return True

success = asyncio.run(main())
sys.exit(0 if success else 1)
```

### Run

```bash
# Against local Docker
python test_token_propagation.py http://localhost:9080/mcp 'YOUR_OPENBRIDGE_TOKEN'

# Against Cloud Run
python test_token_propagation.py https://mcp-rainmaker-sucrey6dia-uk.a.run.app/mcp 'YOUR_OPENBRIDGE_TOKEN'

# Against Cloudflare Worker proxy
python test_token_propagation.py https://mcp-amazon-ads-01.thomas-fde.workers.dev/mcp 'YOUR_OPENBRIDGE_TOKEN'
```

### Expected Output (Success)

```
[PASS] Connected. 3 tools available.

Calling list_identities...
[PASS] list_identities returned 2 identities:
  - ID 14275: Gopal Shah (gopal@rainmakerecommerce.com) region=na
  - ID 15401: Rainmaker Analytics (analytics@rainmakerecommerce.com) region=na

Setting active identity...
[PASS] Set active identity to 14275
[PASS] get_active_identity confirms 14275

Calling summarize_profiles...
[PASS] summarize_profiles: 15 profiles found
  US: 10 profiles
  CA: 3 profiles
  MX: 2 profiles

[ALL PASS] Token propagation verified end-to-end.
```

---

## Test 3: Claude Desktop / mcp-remote Integration

### Config (`claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "amazon_ads": {
      "command": "npx",
      "args": [
        "-y",
        "mcp-remote@latest",
        "https://YOUR_SERVER_URL/mcp",
        "--header",
        "Authorization: Bearer ${OPENBRIDGE_REFRESH_TOKEN}",
        "--header",
        "Accept:application/json,text/event-stream"
      ],
      "env": {
        "OPENBRIDGE_REFRESH_TOKEN": "YOUR_TOKEN_HERE"
      }
    }
  }
}
```

### Manual Verification Steps

1. **Start Claude Desktop** with the config above
2. **Check MCP connection**: Click the MCP icon, verify "amazon_ads" shows connected
3. **Ask Claude**: "List my Amazon Ads identities"
   - Expected: Claude calls `list_identities` and shows identity names/emails
   - If code mode is on, Claude will use `search` → `execute` flow
4. **Ask Claude**: "Set active identity to [ID from step 3]"
5. **Ask Claude**: "Show me a summary of my advertising profiles"
   - Expected: Profile counts by country
6. **Ask Claude**: "What campaigns do I have?"
   - Expected: Campaign data from Amazon Ads API

---

## Test 4: Proxy Header Passthrough (Cloudflare Workers)

If the server is behind a Cloudflare Worker proxy, verify the `Authorization` header is forwarded.

### Verify from Worker Logs

```
# In Cloudflare dashboard → Workers → Logs
# Look for the Authorization header in the request to the origin
```

### Common Proxy Issues

| Symptom | Cause | Fix |
|---------|-------|-----|
| `list_identities` returns empty / "No OpenBridge token" | Authorization header stripped by proxy | Configure proxy to forward `Authorization` header |
| 406 Not Acceptable on GET /mcp | Missing `Accept: text/event-stream` | Add `Accept` header in proxy config |
| 404 on /health | Health check hitting proxy, not origin | Configure health check path in proxy |
| Token works on Cloud Run but not via Worker | Worker consuming the Bearer token for its own auth | Pass token in a custom header (e.g. `X-OpenBridge-Token`) and have middleware check both |

---

## Test 5: Server Logs Checklist

When a tool call succeeds, the server logs should show this sequence:

```
1. RefreshTokenMiddleware - Converting refresh token to JWT (cache miss)...
2. HTTP Request: POST https://authentication.api.openbridge.io/auth/api/refresh "HTTP/1.1 202 Accepted"
3. RefreshTokenMiddleware - Cached new JWT token
4. Processing request of type CallToolRequest
5. Listing remote identities (type=14)
6. Fetching remote identities from OpenBridge (type=14)
7. HTTP Request: POST https://authentication.api.openbridge.io/auth/api/ref "HTTP/1.1 202 Accepted"
8. HTTP Request: GET https://remote-identity.api.openbridge.io/sri?... "HTTP/1.1 200 OK"
9. Found N remote identities
```

**If step 1 is missing**: Middleware is not extracting the token. Check:
- `REFRESH_TOKEN_ENABLED=true` in env
- Server image has `get_http_request()` fallback in `middleware/authentication.py`

**If step 1 appears but step 5 fails with "No OpenBridge token"**: The middleware set the token on a different provider instance. Check for provider singleton issues.

**If step 7 returns 401/403**: The refresh token is invalid or expired. Get a new token from OpenBridge.

---

## Failure Diagnosis Quick Reference

| Error Message | Root Cause | Fix |
|---------------|-----------|-----|
| "No OpenBridge token available. Set OPENBRIDGE_REFRESH_TOKEN..." | Bearer token not reaching the provider | Ensure `AMAZON_ADS_AUTH_METHOD=openbridge`, image has `get_http_request()` fallback |
| "Authentication required: can't compare offset-naive..." | Datetime timezone bug in credential caching | Fixed in this release (test_auth.py timezone fix) |
| "Output validation error: 's3BucketRegion' is a required property" | OpenAPI 3.0/3.1 nullable mismatch | Fixed in this release (nullable normalization in openapi_utils.py) |
| "OpenAPI schema validation failed: 44 validation errors" | `type: "null"` invalid in OpenAPI 3.0 | Fixed in this release (Phase 0 normalization) |
| "Error in error callback" | ErrorHandlingMiddleware callback signature mismatch | Fixed in this release (added `context` param) |
| Empty response from `execute` (code mode) | Code mode sandbox doesn't surface `call_tool` results via `print()` | Call tools directly by name instead of via `execute`; this is a known code mode limitation |

---

## Architecture Reference

```
Client Request Flow:
┌──────────────┐     ┌──────────────────┐     ┌───────────────────┐
│  MCP Client  │────▶│  Cloudflare      │────▶│   Cloud Run       │
│  (Claude,    │     │  Worker (proxy)   │     │   (MCP Server)    │
│   mcp-remote)│     │                  │     │                   │
│              │     │  Must forward:   │     │  Middleware chain: │
│  Sends:      │     │  - Authorization │     │  1. ErrorHandling  │
│  Authorization│     │  - Accept        │     │  2. RefreshToken   │
│  Bearer TOKEN│     │  - Content-Type  │     │     ↓ extracts     │
└──────────────┘     └──────────────────┘     │     Bearer token   │
                                               │     ↓ calls        │
                                               │  provider          │
                                               │  .set_refresh_token│
                                               │     ↓              │
                                               │  OpenBridge API    │
                                               │  (JWT + identities)│
                                               └───────────────────┘
```

**Key invariant**: The `Authorization: Bearer <token>` header must arrive intact at the MCP server's middleware. Any proxy layer that strips, replaces, or consumes this header will break authentication.
