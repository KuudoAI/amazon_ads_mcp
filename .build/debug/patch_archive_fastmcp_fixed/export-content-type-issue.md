# Export Content-Type Issue

## Problem Description

When retrieving export results using `GetExport`, the API returns a 406 error:

```
HTTP error 406: Not Acceptable - {'message': "ExportId provided does not match Content-Type 'application/vnd.adgroupsexport.v1+json'. Content-Type available: 'application/vnd.campaignsexport.v1+json'"}
```

## Root Cause

The Amazon Ads API uses different content types for different export types:
- Campaign exports: `application/vnd.campaignsexport.v1+json`
- Ad Group exports: `application/vnd.adgroupsexport.v1+json`
- Ads exports: `application/vnd.adsexport.v1+json`
- Targets exports: `application/vnd.targetsexport.v1+json`

When calling `GET /exports/{exportId}`, the server determines which content-type to use based on the export ID itself. However, the MCP client doesn't know which content-type to request without tracking what type of export was created.

## Current Behavior

1. User calls `CampaignExport` → receives export ID
2. User calls `GetExport` with that ID
3. System defaults to requesting with `application/vnd.adgroupsexport.v1+json` (first in the list)
4. Server rejects because the export is actually a campaign export

## Solutions

### Solution 1: Export ID Tracking (Recommended)

Track export IDs with their types in the MCP session state:

```python
# When creating an export
export_id = response["exportId"]
export_type = "campaign"  # Based on which export endpoint was called
session_state[f"export_{export_id}"] = export_type

# When retrieving an export
export_type = session_state.get(f"export_{export_id}", "unknown")
content_type = EXPORT_CONTENT_TYPES[export_type]
```

### Solution 2: Try All Content Types

When GetExport fails with 406, parse the error message to get the correct content-type and retry:

```python
try:
    # Try with default content-type
    result = get_export(export_id)
except HTTPError as e:
    if e.status_code == 406:
        # Parse the correct content-type from error message
        # Retry with correct content-type
        pass
```

### Solution 3: Export ID Encoding

If the export ID encodes the type (which it appears to do), decode it to determine the content-type:

```python
def get_export_type_from_id(export_id: str) -> str:
    # The export ID might encode the type
    # Need to understand Amazon's encoding scheme
    pass
```

## Temporary Workaround

For now, users can:
1. Use the specific export retrieval endpoints if they exist
2. Query data directly using the regular API endpoints instead of exports
3. Wait for the fix to be implemented

## Implementation Priority

This should be fixed in the MCP server by:
1. Tracking export IDs to their types in session state
2. Using the correct content-type when calling GetExport
3. Providing clear error messages to users about export status