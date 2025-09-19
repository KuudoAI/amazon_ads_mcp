# Export Content-Type Resolution Solution

## Problem
Amazon Ads API exports require specific content-types based on the export type, but the API returns 406 errors when the wrong content-type is used.

## Solution 
We discovered that Amazon export IDs encode the export type as a suffix in base64:

- Export ID format: `base64(UUID,TYPE)`
- Example: `OTc2MDhjNmEtNDg3Zi00YzMyLTllOWEtMDMwNjNhYTk1MGM0LEM`
- Decodes to: `97608c6a-487f-4c32-9e9a-03063aa950c4,C`

The suffix indicates the export type:
- `,C` = Campaign export → `application/vnd.campaignsexport.v1+json`
- `,A` = Ad Group export → `application/vnd.adgroupsexport.v1+json`
- `,AD` = Ads export → `application/vnd.adsexport.v1+json`
- `,T` = Targets export → `application/vnd.targetsexport.v1+json`

## Implementation

### 1. Export Content-Type Resolver
Created `/src/amazon_ads_mcp/utils/export_content_type_resolver.py`:
- Decodes export IDs to extract the type suffix
- Maps suffix to correct content-type
- Provides fallback logic if pattern doesn't match

### 2. MediaTypeRegistry Integration
Modified `/src/amazon_ads_mcp/server/mcp_server_mounted.py`:
- Special handling for `/exports/` endpoints
- Extracts export ID from URL
- Uses resolver to determine correct content-type
- Falls back to default behavior if resolution fails

## How It Works

1. When `GET /exports/{exportId}` is called:
   - Extract the export ID from the URL
   - Decode the base64 to get the type suffix
   - Map suffix to the appropriate content-type
   - Set the Accept header to that content-type

2. The server accepts the correct content-type and returns the export data

## Benefits

- No hacky export tracking needed
- Works with the existing MediaTypeRegistry pattern
- Stateless - doesn't require session state
- Handles all export types automatically
- Graceful fallback if pattern changes

## Testing

```python
from src.amazon_ads_mcp.utils.export_content_type_resolver import resolve_export_content_type

# Campaign export
export_id = "OTc2MDhjNmEtNDg3Zi00YzMyLTllOWEtMDMwNjNhYTk1MGM0LEM"
assert resolve_export_content_type(export_id) == "application/vnd.campaignsexport.v1+json"
```

## Future Improvements

If Amazon changes the export ID format, we can:
1. Update the pattern matching in the resolver
2. Add additional heuristics
3. Fall back to trying multiple content-types in order