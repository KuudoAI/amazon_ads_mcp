#!/usr/bin/env python3
"""
Apply FastMCP schema preservation fix.

This script applies the necessary patches to FastMCP to ensure
nested schema definitions are preserved when serving OpenAPI tools.
"""

import os
import sys
from pathlib import Path
import site

def find_fastmcp_path():
    """Find the FastMCP installation path."""
    # Check all site-packages directories
    for site_dir in site.getsitepackages():
        fastmcp_path = Path(site_dir) / "fastmcp"
        if fastmcp_path.exists():
            return fastmcp_path
    
    # Check virtual environment
    if hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
        venv_site = Path(sys.prefix) / "lib"
        for python_dir in venv_site.glob("python*"):
            fastmcp_path = python_dir / "site-packages" / "fastmcp"
            if fastmcp_path.exists():
                return fastmcp_path
    
    return None

def apply_legacy_parser_fix(fastmcp_path):
    """Apply fix to legacy OpenAPI parser."""
    legacy_file = fastmcp_path / "utilities" / "openapi.py"
    
    if not legacy_file.exists():
        print(f"❌ Legacy parser not found at {legacy_file}")
        return False
    
    with open(legacy_file, 'r') as f:
        content = f.read()
    
    # Fix 1: Remove incorrect condition
    old_line = '    if schema_definitions and "$ref" not in schema.copy():'
    new_line = '    if schema_definitions:'
    
    if old_line in content:
        content = content.replace(old_line, new_line)
        with open(legacy_file, 'w') as f:
            f.write(content)
        print(f"✅ Fixed legacy parser condition at line ~1558")
    else:
        print("ℹ️  Legacy parser already fixed or has different code")
    
    return True

def apply_new_parser_fix(fastmcp_path):
    """Apply fix to new experimental OpenAPI parser."""
    new_file = fastmcp_path / "experimental" / "utilities" / "openapi" / "schemas.py"
    
    if not new_file.exists():
        print(f"❌ New parser not found at {new_file}")
        return False
    
    with open(new_file, 'r') as f:
        content = f.read()
    
    # Fix 1: Remove incorrect condition
    old_line = '    if schema_definitions and "$ref" not in schema.copy():'
    new_line = '    if schema_definitions:'
    
    fixes_applied = 0
    
    if old_line in content:
        content = content.replace(old_line, new_line)
        fixes_applied += 1
        print(f"✅ Fixed new parser condition at line ~478")
    
    # Fix 2: Add transitive closure if not present
    if 'while len(used_refs) > previous_size:' not in content:
        # Find the location to insert the transitive closure
        marker = '        # Find refs in the main schema (excluding $defs section)\n' + \
                '        for key, value in output_schema.items():\n' + \
                '            if key != "$defs":\n' + \
                '                find_refs_in_value(value)\n\n' + \
                '        # Remove unused definitions'
        
        replacement = '        # Find refs in the main schema (excluding $defs section)\n' + \
                     '        for key, value in output_schema.items():\n' + \
                     '            if key != "$defs":\n' + \
                     '                find_refs_in_value(value)\n\n' + \
                     '        # Recursively find transitive dependencies in the $defs section\n' + \
                     '        # Keep adding until no new refs are found (transitive closure)\n' + \
                     '        previous_size = 0\n' + \
                     '        while len(used_refs) > previous_size:\n' + \
                     '            previous_size = len(used_refs)\n' + \
                     '            # Check each currently used definition for additional refs\n' + \
                     '            for ref_name in list(used_refs):  # Copy to avoid modification during iteration\n' + \
                     '                if ref_name in output_schema["$defs"]:\n' + \
                     '                    find_refs_in_value(output_schema["$defs"][ref_name])\n\n' + \
                     '        # Remove unused definitions'
        
        if marker in content:
            content = content.replace(marker, replacement)
            fixes_applied += 1
            print(f"✅ Added transitive closure algorithm to new parser")
    
    if fixes_applied > 0:
        with open(new_file, 'w') as f:
            f.write(content)
        print(f"✅ Applied {fixes_applied} fixes to new parser")
    else:
        print("ℹ️  New parser already fixed or has different code")
    
    return True

def main():
    print("FastMCP Schema Preservation Fix Applicator")
    print("=" * 50)
    
    # Find FastMCP installation
    fastmcp_path = find_fastmcp_path()
    
    if not fastmcp_path:
        print("❌ Could not find FastMCP installation")
        print("Make sure FastMCP is installed: pip install fastmcp")
        return 1
    
    print(f"Found FastMCP at: {fastmcp_path}")
    print()
    
    # Apply fixes
    print("Applying fixes...")
    legacy_ok = apply_legacy_parser_fix(fastmcp_path)
    new_ok = apply_new_parser_fix(fastmcp_path)
    
    print()
    if legacy_ok and new_ok:
        print("✅ All fixes applied successfully!")
        print("\nNext steps:")
        print("1. Restart your MCP server")
        print("2. Test with Claude Desktop or your MCP client")
        return 0
    else:
        print("⚠️  Some fixes could not be applied")
        print("You may need to apply them manually - see fastmcp-schema-preservation-fix.md")
        return 1

if __name__ == "__main__":
    sys.exit(main())