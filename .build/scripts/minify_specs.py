#!/usr/bin/env python3
"""
Minify OpenAPI specifications for production deployment.

This creates minified versions of specs in a dist/ directory,
while keeping the source files readable for development.
"""

import json
import sys
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parents[2]
RESOURCES_DIR = ROOT / "openapi" / "resources"
DIST_DIR = ROOT / "dist" / "openapi" / "resources"


def minify_json_file(input_path: Path, output_path: Path) -> int:
    """Minify a single JSON file.
    
    Returns the size reduction in bytes.
    """
    with open(input_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # Original size
    original_size = input_path.stat().st_size
    
    # Write minified version
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, separators=(',', ':'), ensure_ascii=False)
    
    # New size
    minified_size = output_path.stat().st_size
    
    return original_size - minified_size


def main():
    """Minify all OpenAPI specs for production."""
    if not RESOURCES_DIR.exists() or not list(RESOURCES_DIR.glob("*.json")):
        print(f"❌ No OpenAPI specs found at {RESOURCES_DIR}")
        print(f"   Please run 'make download-specs' to download the specifications first")
        return 1
    
    print(f"📦 Minifying OpenAPI specs to {DIST_DIR}")
    
    total_original = 0
    total_minified = 0
    file_count = 0
    
    for spec_path in sorted(RESOURCES_DIR.glob("*.json")):
        # Skip sidecar files
        if spec_path.stem.endswith((".media", ".manifest", ".transform")):
            continue
        if spec_path.name in {"packages.json", "manifest.json"}:
            continue
        
        output_path = DIST_DIR / spec_path.name
        
        try:
            original_size = spec_path.stat().st_size
            saved = minify_json_file(spec_path, output_path)
            minified_size = output_path.stat().st_size
            
            total_original += original_size
            total_minified += minified_size
            file_count += 1
            
            reduction_pct = (saved / original_size) * 100 if original_size > 0 else 0
            print(f"  ✓ {spec_path.name}: {original_size:,} → {minified_size:,} bytes (-{reduction_pct:.1f}%)")
            
        except Exception as e:
            print(f"  ✗ {spec_path.name}: {e}")
            continue
    
    if file_count > 0:
        total_saved = total_original - total_minified
        total_reduction = (total_saved / total_original) * 100 if total_original > 0 else 0
        
        print(f"\n📊 Summary:")
        print(f"  Files processed: {file_count}")
        print(f"  Original size: {total_original:,} bytes ({total_original / 1024 / 1024:.1f} MB)")
        print(f"  Minified size: {total_minified:,} bytes ({total_minified / 1024 / 1024:.1f} MB)")
        print(f"  Space saved: {total_saved:,} bytes ({total_saved / 1024 / 1024:.1f} MB)")
        print(f"  Reduction: {total_reduction:.1f}%")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())