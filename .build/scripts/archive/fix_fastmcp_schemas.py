#!/usr/bin/env python3
"""
Fix FastMCP schema transformation issues.

FastMCP transforms #/components/schemas/ references to #/$defs/ 
but doesn't actually move the schemas. This script fixes that.
"""
import json
from pathlib import Path
from typing import Dict, Any

def transform_refs(obj: Any, old_prefix: str = "#/components/schemas/", new_prefix: str = "#/$defs/") -> Any:
    """Recursively transform all $ref values in an object."""
    if isinstance(obj, dict):
        result = {}
        for key, value in obj.items():
            if key == "$ref" and isinstance(value, str) and value.startswith(old_prefix):
                # Transform the reference
                schema_name = value[len(old_prefix):]
                result[key] = new_prefix + schema_name
            else:
                result[key] = transform_refs(value, old_prefix, new_prefix)
        return result
    elif isinstance(obj, list):
        return [transform_refs(item, old_prefix, new_prefix) for item in obj]
    else:
        return obj

def add_defs_section(spec: Dict[str, Any]) -> Dict[str, Any]:
    """Add a $defs section that duplicates components/schemas for FastMCP compatibility."""
    if "components" in spec and "schemas" in spec.get("components", {}):
        # Create $defs as a copy of components/schemas
        spec["$defs"] = spec["components"]["schemas"].copy()
        
        # Transform any refs within $defs to use $defs instead of components/schemas
        spec["$defs"] = transform_refs(spec["$defs"], "#/components/schemas/", "#/$defs/")
    
    return spec

def fix_spec(spec_path: Path) -> None:
    """Fix a single OpenAPI spec for FastMCP compatibility."""
    print(f"Fixing {spec_path.name}...")
    
    with open(spec_path, 'r') as f:
        spec = json.load(f)
    
    # Add $defs section
    original_schemas = len(spec.get("components", {}).get("schemas", {}))
    spec = add_defs_section(spec)
    
    if "$defs" in spec:
        print(f"  Added $defs section with {len(spec['$defs'])} schemas")
    
    # Write back
    with open(spec_path, 'w') as f:
        json.dump(spec, f, indent=2, sort_keys=True)
    
    print(f"  ✅ Fixed {spec_path.name}")

def main():
    """Fix all OpenAPI specs in resources directory."""
    resources_dir = Path("openapi/resources")
    
    if not resources_dir.exists():
        print(f"Error: {resources_dir} does not exist")
        return
    
    spec_files = list(resources_dir.glob("*.json"))
    spec_files = [f for f in spec_files if not f.name.endswith(".media.json")]
    
    print(f"Found {len(spec_files)} OpenAPI specs to fix")
    print("=" * 60)
    
    for spec_file in spec_files:
        try:
            fix_spec(spec_file)
        except Exception as e:
            print(f"  ❌ Error fixing {spec_file.name}: {e}")
    
    print("=" * 60)
    print("✅ Done! Restart the MCP server to use the fixed schemas.")

if __name__ == "__main__":
    main()