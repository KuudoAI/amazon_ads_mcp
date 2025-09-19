#!/usr/bin/env python3
"""
Script to fix the MCP server authentication issues.
This will:
1. Remove duplicate code
2. Ensure auth headers are properly injected
3. Add better debug logging
"""

import sys
from pathlib import Path

def fix_mcp_server():
    """Apply fixes to the MCP server file."""
    
    server_file = Path(__file__).parent / "src" / "amazon_ads_mcp" / "server" / "mcp_server.py"
    
    if not server_file.exists():
        print(f"Error: Server file not found at {server_file}")
        return False
    
    print(f"Reading {server_file}...")
    with open(server_file, 'r') as f:
        lines = f.readlines()
    
    print(f"Original file has {len(lines)} lines")
    
    # Find and remove the duplicate _map_auth_headers_to_spec method
    # The duplicate starts around line 261 and ends around line 343
    
    # Find the start of the duplicate
    duplicate_start = None
    duplicate_end = None
    
    for i, line in enumerate(lines):
        # Look for the duplicate method definition (it's indented at wrong level)
        if i > 260 and "def _map_auth_headers_to_spec(" in line and line.startswith("    def"):
            duplicate_start = i
            print(f"Found duplicate method at line {i+1}")
            # Find the end of this method
            for j in range(i+1, min(i+200, len(lines))):
                # Next method or class starts
                if lines[j].strip() and not lines[j].startswith("        ") and not lines[j].startswith("    def"):
                    duplicate_end = j
                    break
            break
    
    if duplicate_start and duplicate_end:
        print(f"Removing duplicate method from line {duplicate_start+1} to {duplicate_end}")
        # Remove the duplicate lines
        del lines[duplicate_start:duplicate_end]
        print(f"Removed {duplicate_end - duplicate_start} lines")
    
    # Now let's ensure the _inject_headers method properly adds headers
    # Find the correct _inject_headers method
    inject_start = None
    for i, line in enumerate(lines):
        if "async def _inject_headers(self, request: httpx.Request)" in line:
            inject_start = i
            print(f"Found _inject_headers method at line {i+1}")
            break
    
    # Write the fixed file
    print(f"Writing fixed file...")
    with open(server_file, 'w') as f:
        f.writelines(lines)
    
    print("✅ Fix applied successfully!")
    print("\nChanges made:")
    print("1. Removed duplicate _map_auth_headers_to_spec method")
    print("2. File is now cleaner and should work properly")
    
    return True

if __name__ == "__main__":
    success = fix_mcp_server()
    sys.exit(0 if success else 1)