# FastMCP Schema Preservation Patches

This directory contains patches and documentation for fixing schema preservation issues in FastMCP when serving OpenAPI-generated tools to MCP clients.

## Files

- **`fastmcp-schema-preservation-fix.md`** - Detailed documentation of the issue, root cause, and manual fix instructions
- **`apply-fastmcp-fix.py`** - Automated script to apply the fixes to your FastMCP installation
- **`README.md`** - This file

## Quick Start

### Automatic Fix

Run the patch script to automatically apply the fixes:

```bash
# From the project root
python patch/apply-fastmcp-fix.py

# Or with virtual environment
.venv/bin/python patch/apply-fastmcp-fix.py
```

### Manual Fix

If the automatic script doesn't work, follow the detailed instructions in `fastmcp-schema-preservation-fix.md`.

## The Issue

FastMCP was dropping nested schema definitions (`$defs`) when serving OpenAPI-generated tools, causing validation errors in MCP clients like Claude Desktop:

```
PointerToNowhere: '/$defs/AccountInfo' does not exist
```

## The Solution

The fix involves:

1. **Removing an incorrect condition** that prevented `$defs` from being added when schemas contained `$ref`
2. **Adding transitive closure** to the new parser to find all nested schema dependencies
3. **Enabling the new parser** with the `FASTMCP_EXPERIMENTAL_ENABLE_NEW_OPENAPI_PARSER` environment variable

## Verification

After applying the fix:

1. Restart your MCP server
2. Test with Claude Desktop or run:

```bash
# Test that schemas are preserved
.venv/bin/python -c "
from fastmcp import FastMCP
import json
import httpx
import asyncio

with open('openapi/resources/AccountsProfiles.json') as f:
    spec = json.load(f)

server = FastMCP.from_openapi(spec, httpx.AsyncClient(), 'test')
tools = asyncio.run(server.get_tools())

for name, tool in tools.items():
    if 'listProfiles' in name:
        schema = tool.to_mcp_tool().model_dump().get('outputSchema', {})
        if '$defs' in schema:
            print('✅ Fix working! $defs:', list(schema['$defs'].keys()))
        else:
            print('❌ Fix not applied - no $defs found')
"
```

Expected output:
```
✅ Fix working! $defs: ['AccountInfo', 'AccountType', 'Profile', 'countryCode']
```

## Contributing

This fix should be contributed upstream to FastMCP. The issue affects both:
- Legacy parser: `/fastmcp/utilities/openapi.py`
- New parser: `/fastmcp/experimental/utilities/openapi/schemas.py`

## Related Issues

- FastMCP PR #1386 - Initial transitive closure implementation
- FastMCP PR #1408 - Extended nested schema support

These PRs partially addressed the issue but missed the root cause: the incorrect condition that skipped `$defs` when `$ref` was present in the schema.