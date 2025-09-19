#!/usr/bin/env python3
"""
Fix FastMCP transitive reference issue.

FastMCP (as of 2.11.1) doesn't include all transitively referenced schemas in $defs.
This script ensures all referenced schemas are included, implementing a transitive closure.

See: https://github.com/jlowin/fastmcp/issues/1372
"""
import json
from pathlib import Path
from typing import Dict, Any, Set

def extract_refs(obj: Any, refs: Set[str] = None) -> Set[str]:
    """Extract all $ref values from an object recursively."""
    if refs is None:
        refs = set()
    
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key == "$ref" and isinstance(value, str):
                refs.add(value)
            else:
                extract_refs(value, refs)
    elif isinstance(obj, list):
        for item in obj:
            extract_refs(item, refs)
    
    return refs

def get_schema_name(ref: str) -> str:
    """Extract schema name from a $ref."""
    if ref.startswith("#/components/schemas/"):
        return ref[len("#/components/schemas/"):]
    elif ref.startswith("#/$defs/"):
        return ref[len("#/$defs/"):]
    return None

def transform_ref(ref: str) -> str:
    """Transform a components/schemas ref to $defs."""
    if ref.startswith("#/components/schemas/"):
        schema_name = ref[len("#/components/schemas/"):]
        return f"#/$defs/{schema_name}"
    return ref

def transform_refs_in_schema(obj: Any) -> Any:
    """Recursively transform all refs from components/schemas to $defs."""
    if isinstance(obj, dict):
        result = {}
        for key, value in obj.items():
            if key == "$ref" and isinstance(value, str):
                result[key] = transform_ref(value)
            else:
                result[key] = transform_refs_in_schema(value)
        return result
    elif isinstance(obj, list):
        return [transform_refs_in_schema(item) for item in obj]
    else:
        return obj

def compute_transitive_closure(spec: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compute transitive closure of all schemas referenced in the spec.
    Returns a complete $defs section with all transitively referenced schemas.
    """
    if "components" not in spec or "schemas" not in spec.get("components", {}):
        return {}
    
    all_schemas = spec["components"]["schemas"]
    defs = {}
    
    # Start with schemas directly referenced in paths
    paths = spec.get("paths", {})
    initial_refs = extract_refs(paths)
    
    # Also include all schemas (for completeness)
    for name in all_schemas:
        initial_refs.add(f"#/components/schemas/{name}")
    
    # Build transitive closure
    to_process = list(initial_refs)
    processed = set()
    
    while to_process:
        ref = to_process.pop(0)
        if ref in processed:
            continue
        processed.add(ref)
        
        schema_name = get_schema_name(ref)
        if not schema_name:
            continue
        
        if schema_name in all_schemas:
            # Transform refs within this schema
            transformed_schema = transform_refs_in_schema(all_schemas[schema_name])
            defs[schema_name] = transformed_schema
            
            # Find refs within this schema and add to processing queue
            nested_refs = extract_refs(transformed_schema)
            for nested_ref in nested_refs:
                if nested_ref not in processed:
                    # Convert $defs refs back to components/schemas for lookup
                    if nested_ref.startswith("#/$defs/"):
                        lookup_ref = f"#/components/schemas/{nested_ref[len('#/$defs/'):]}"
                        to_process.append(lookup_ref)
    
    return defs

def fix_spec(spec_path: Path) -> None:
    """Fix a single OpenAPI spec for FastMCP compatibility."""
    print(f"Fixing {spec_path.name}...")
    
    with open(spec_path, 'r') as f:
        spec = json.load(f)
    
    # Compute transitive closure and add $defs
    defs = compute_transitive_closure(spec)
    
    if defs:
        spec["$defs"] = defs
        print(f"  Added $defs with {len(defs)} schemas (transitive closure)")
    
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