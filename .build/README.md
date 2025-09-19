# OpenAPI Spec Post-Processing System

This directory contains the infrastructure for post-processing OpenAPI specifications to fix issues, apply security defaults, and ensure compatibility with FastMCP.

## Overview

The post-processing system runs a pipeline of transforms on OpenAPI specs:

1. **Common Transforms** - Applied to all specs (normalization, cleanup)
2. **Safety Defaults** - Security-focused parameter defaults
3. **Targeted Patches** - Spec-specific fixes for known issues

## Structure

```
.build/
├── scripts/
│   └── process_openapi_specs.py    # Main CLI tool
├── spec_patches/
│   ├── common.py                   # Common transforms for all specs
│   ├── safety_defaults.py          # Security/safety overrides
│   ├── registry.py                 # Patch discovery and registration
│   └── patches/                    # Spec-specific patches
│       ├── AccountsAdsAccounts.py  # Fix for list response schema
│       └── AccountsProfiles.py     # Change accessLevel default
└── spec_utils/
    └── io.py                       # JSON I/O utilities
```

## Usage

### Process All Specs
```bash
# Apply all fixes
make process-specs

# Check for issues (CI mode - exits non-zero if changes needed)
make check-specs

# Preview changes without applying
make diff-specs
```

### Process Single Spec
```bash
# Fix a specific spec
make fix-single-spec SPEC=AccountsAdsAccounts

# Or using the script directly
python .build/scripts/process_openapi_specs.py --only AccountsAdsAccounts --fix --diff
```

### CI Integration
```yaml
# GitHub Actions example
- name: Check OpenAPI specs
  run: make check-specs
```

## Adding New Patches

### 1. Common Transform
Edit `.build/spec_patches/common.py` to add transforms that apply to all specs:

```python
def apply_common_transforms(spec: Dict[str, Any]) -> Tuple[bool, List[str]]:
    # Add your transform here
    # Return (changed: bool, notes: List[str])
```

### 2. Targeted Patch
Create a new file `.build/spec_patches/patches/YourNamespace.py`:

```python
from typing import Any, Dict, List, Tuple

def patch_something(spec: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Fix something specific in this namespace."""
    notes = []
    changed = False
    
    # Your patch logic here
    # Must be idempotent!
    
    return changed, notes

# Register patches
PATCHES = [patch_something]
```

### 3. Safety Defaults
Edit `.build/spec_patches/safety_defaults.py` to add new safety rules:

```python
SAFER_DEFAULTS = {
    "paramName": (unsafe_value, safe_value, "reason"),
}
```

## Examples of Current Patches

### AccountsAdsAccounts - Response Schema Fix
**Problem**: `/adsAccounts/list` returns an object with `adsAccounts` array, but spec declared it as a bare array.

**Solution**: Transform response schema from `type: array` to `type: object` with `adsAccounts` property.

### AccountsProfiles - Safety Default
**Problem**: `accessLevel` parameter defaults to `"edit"` which is too permissive.

**Solution**: Change default to `"view"` following principle of least privilege.

## Design Principles

1. **Idempotent** - Patches can be run multiple times safely
2. **Minimal** - Only change what's necessary
3. **Traceable** - All changes are logged with reasons
4. **Testable** - Use `--check` and `--diff` to verify changes
5. **Extensible** - Easy to add new patches via registry pattern

## Validation

The processor includes minimal validation to catch obvious issues:
- Missing `openapi` key
- No paths defined
- Operations without 2xx responses

These are warnings, not errors, to avoid blocking on cosmetic issues.

## Best Practices

1. **Test patches individually** before applying to all specs
2. **Document the reason** for each patch in the function docstring
3. **Keep patches focused** - one issue per patch function
4. **Make patches defensive** - check types and structure before modifying
5. **Use `--diff` flag** to review changes before applying

## Troubleshooting

### Patch not applying?
- Check that the patch is registered in `PATCHES` list
- Verify the namespace matches the filename
- Use `--diff` to see if changes are detected

### CI failing on check-specs?
- Run `make process-specs` locally to apply fixes
- Commit the updated spec files
- The patches are meant to be applied and committed, not run dynamically

### Need to revert changes?
- Use git to revert the spec files
- Patches are idempotent, so you can always re-run them