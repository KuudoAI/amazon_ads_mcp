# FastMCP Schema Preservation Fix

## Issue Description

When using FastMCP to serve OpenAPI-generated tools to MCP clients (like Claude Desktop), nested schema definitions (`$defs`) were being lost during transmission, causing "PointerToNowhere" errors.

### Symptoms
- Claude Desktop would throw errors like: `PointerToNowhere: '/$defs/AccountInfo' does not exist`
- Tools with complex nested schemas (e.g., `profiles_listProfiles`) would fail validation
- Only the directly referenced schema would be preserved, not its dependencies

### Root Cause
FastMCP had a bug in both its legacy and new OpenAPI parsers where it would skip adding `$defs` to output schemas if the main schema contained a `$ref`. Additionally, the transitive closure algorithm for finding nested dependencies was missing in the new parser.

## Affected Files

1. **Legacy Parser**: `/fastmcp/utilities/openapi.py`
2. **New Parser**: `/fastmcp/experimental/utilities/openapi/schemas.py`

## The Fix

### Part 1: Legacy Parser Fix

**File**: `.venv/lib/python3.13/site-packages/fastmcp/utilities/openapi.py`

**Line 1558 - Before**:
```python
# Only add $defs if we didn't resolve the $ref inline above
if schema_definitions and "$ref" not in schema.copy():
    processed_defs = {}
    # ... rest of code
```

**Line 1558 - After**:
```python
# Always add $defs when they exist - they may be needed for nested references
if schema_definitions:
    processed_defs = {}
    # ... rest of code
```

**Explanation**: The condition `"$ref" not in schema.copy()` was incorrectly preventing `$defs` from being added when the main schema contained any `$ref`. Since schemas like `{"items": {"$ref": "#/$defs/Profile"}}` contain references, this would skip adding all the schema definitions.

### Part 2: New Parser Fix

**File**: `.venv/lib/python3.13/site-packages/fastmcp/experimental/utilities/openapi/schemas.py`

#### Fix 1: Remove incorrect condition (Line 478)

**Before**:
```python
# Only add $defs if we didn't resolve the $ref inline above
if schema_definitions and "$ref" not in schema.copy():
```

**After**:
```python
# Always add $defs when they exist - they may be needed for nested references
if schema_definitions:
```

#### Fix 2: Add transitive closure algorithm (After line 515)

**Before**:
```python
# Find refs in the main schema (excluding $defs section)
for key, value in output_schema.items():
    if key != "$defs":
        find_refs_in_value(value)

# Remove unused definitions
```

**After**:
```python
# Find refs in the main schema (excluding $defs section)
for key, value in output_schema.items():
    if key != "$defs":
        find_refs_in_value(value)

# Recursively find transitive dependencies in the $defs section
# Keep adding until no new refs are found (transitive closure)
previous_size = 0
while len(used_refs) > previous_size:
    previous_size = len(used_refs)
    # Check each currently used definition for additional refs
    for ref_name in list(used_refs):  # Copy to avoid modification during iteration
        if ref_name in output_schema["$defs"]:
            find_refs_in_value(output_schema["$defs"][ref_name])

# Remove unused definitions
```

**Explanation**: The new parser was only checking for direct references in the main schema but not following nested references within `$defs`. For example, if `Profile` references `AccountInfo`, and `AccountInfo` references `AccountType`, the algorithm needs to recursively find all these dependencies.

## Server Configuration

To use the new parser (recommended after applying the fixes), add this environment variable:

**File**: `src/amazon_ads_mcp/server/mcp_server_mounted.py`

Add at the top of the file, before FastMCP imports:
```python
# Enable the new OpenAPI parser in FastMCP (must be before import)
os.environ["FASTMCP_EXPERIMENTAL_ENABLE_NEW_OPENAPI_PARSER"] = "true"
```

## Testing the Fix

### Test Script
Create a test script to verify schemas are transmitted correctly:

```python
#!/usr/bin/env python3
import asyncio
import json
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def test_schemas():
    server_params = StdioServerParameters(
        command=".venv/bin/python",
        args=["-m", "src.amazon_ads_mcp.server.mcp_server_mounted"],
        env={"PYTHONPATH": "."}
    )
    
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            
            tools = await session.list_tools()
            
            for tool in tools.tools:
                if 'listProfiles' in tool.name:
                    print(f"Found tool: {tool.name}")
                    
                    if tool.outputSchema and '$defs' in tool.outputSchema:
                        defs_keys = list(tool.outputSchema['$defs'].keys())
                        print(f"Has $defs: {defs_keys}")
                        
                        expected = ['AccountInfo', 'AccountType', 'Profile', 'countryCode']
                        missing = [k for k in expected if k not in defs_keys]
                        
                        if missing:
                            print(f"❌ Missing schemas: {missing}")
                        else:
                            print("✅ All schemas present!")
                    return

asyncio.run(test_schemas())
```

### Expected Output
```
Found tool: profiles_listProfiles
Has $defs: ['AccountInfo', 'AccountType', 'Profile', 'countryCode']
✅ All schemas present!
```

## Verification in Claude Desktop

After applying the fixes:

1. Start the server: `python -m amazon_ads_mcp.server.mcp_server_mounted --transport http --port 9080`
2. Configure Claude Desktop to connect to the server
3. Test with a command like "get my ad profiles"
4. The tool should execute successfully without "PointerToNowhere" errors

## Related PRs

This fix is related to:
- FastMCP PR #1386: Initial transitive closure implementation (partially working)
- FastMCP PR #1408: Extended fix for nested schema dependencies

Our fix completes what these PRs attempted by:
1. Removing the incorrect condition that prevented `$defs` from being added
2. Ensuring transitive closure works in both legacy and new parsers

## Impact

This fix ensures that all OpenAPI-generated tools with complex nested schemas work correctly with MCP clients, preserving the complete schema definition hierarchy needed for proper validation and type checking.

## Permanent Solution

For a permanent fix, these changes should be submitted as a PR to the FastMCP repository. Until then, this patch must be applied after installing/updating FastMCP.