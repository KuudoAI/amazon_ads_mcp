#!/usr/bin/env python3
"""
Build production-ready OpenAPI specs and assets.

This script:
1. Processes specs with patches (fixes)
2. Minifies specs for production
3. Copies sidecar files
4. Creates dist/ directory structure
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, Any

ROOT = Path(__file__).resolve().parents[2]
RESOURCES_DIR = ROOT / "openapi" / "resources"
DIST_DIR = ROOT / "dist" / "openapi" / "resources"

# Import processing utilities
sys.path.insert(0, str((ROOT / ".build").resolve()))
from spec_utils.io import load_json, save_json  # type: ignore


def run_command(cmd: list[str], description: str) -> bool:
    """Run a command and return success status."""
    print(f"🔧 {description}...")
    try:
        result = subprocess.run(
            cmd,
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True
        )
        if result.stdout:
            print(f"  {result.stdout.strip()}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"  ❌ Failed: {e}")
        if e.stderr:
            print(f"  {e.stderr.strip()}")
        return False


def minify_and_copy_spec(input_path: Path, output_path: Path) -> bool:
    """Minify a spec file and copy to dist."""
    try:
        # Load the spec
        data = load_json(input_path)
        
        # Ensure output directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Write minified version
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, separators=(',', ':'), ensure_ascii=False)
        
        # Report size difference
        original_size = input_path.stat().st_size
        minified_size = output_path.stat().st_size
        reduction_pct = ((original_size - minified_size) / original_size * 100) if original_size > 0 else 0
        
        print(f"  ✓ {input_path.name}: {original_size:,} → {minified_size:,} bytes (-{reduction_pct:.1f}%)")
        return True
        
    except Exception as e:
        print(f"  ❌ {input_path.name}: {e}")
        return False


def copy_sidecar_files():
    """Copy sidecar files (manifest, transform, media) to dist."""
    print("\n📄 Copying sidecar files...")
    copied = 0
    
    # Ensure resources directory exists
    if not RESOURCES_DIR.exists():
        print(f"  ⚠️  No resources directory, skipping sidecar files")
        return
    
    for pattern in ["*.manifest.json", "*.transform.json", "*.media.json"]:
        for sidecar in RESOURCES_DIR.glob(pattern):
            dest = DIST_DIR / sidecar.name
            try:
                # These files are typically already minified, just copy
                shutil.copy2(sidecar, dest)
                copied += 1
                print(f"  ✓ {sidecar.name}")
            except Exception as e:
                print(f"  ❌ {sidecar.name}: {e}")
    
    # Also copy packages.json if it exists
    packages = RESOURCES_DIR / "packages.json"
    if packages.exists():
        dest = DIST_DIR / "packages.json"
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(packages, dest)
        print(f"  ✓ packages.json")
        copied += 1
    
    print(f"  📦 Copied {copied} sidecar files")


def main():
    """Build production assets."""
    print("🚀 Building production OpenAPI assets\n")
    
    # Step 0: Check if specs exist, download if needed
    if not RESOURCES_DIR.exists() or not list(RESOURCES_DIR.glob("*.json")):
        print("Step 0: Downloading OpenAPI specifications")
        download_script = ROOT / "scripts" / "download_openapi_specs.py"
        if download_script.exists():
            if not run_command(
                ["python", str(download_script)],
                "Downloading specs"
            ):
                print("❌ Failed to download specs")
                return 1
            
            merge_script = ROOT / "scripts" / "merge_specs.py"
            if merge_script.exists():
                if not run_command(
                    ["python", str(merge_script)],
                    "Merging specs"
                ):
                    print("⚠️  Warning: Merge failed, continuing...")
        else:
            print("❌ No specs found and download script not available")
            print("   Please run 'make download-specs' first")
            return 1
    
    # Step 1: Process specs with patches
    print("\nStep 1: Processing specs with patches")
    if not run_command(
        ["python", ".build/scripts/process_openapi_specs.py", "--fix", "--skip-download"],
        "Applying spec patches"
    ):
        print("⚠️  Warning: Spec processing failed, continuing anyway...")
    
    # Step 2: Clean dist directory
    print("\nStep 2: Preparing dist directory")
    if DIST_DIR.exists():
        print(f"  🗑️  Cleaning existing dist at {DIST_DIR}")
        shutil.rmtree(DIST_DIR)
    DIST_DIR.mkdir(parents=True, exist_ok=True)
    
    # Step 3: Minify and copy specs
    print("\nStep 3: Minifying OpenAPI specifications")
    success_count = 0
    fail_count = 0
    total_original = 0
    total_minified = 0
    
    # Check if resources directory exists
    if not RESOURCES_DIR.exists():
        print(f"  ⚠️  No resources directory at {RESOURCES_DIR}")
        print(f"     Creating directory...")
        RESOURCES_DIR.mkdir(parents=True, exist_ok=True)
        print(f"     No specs to minify yet.")
    
    for spec_path in sorted(RESOURCES_DIR.glob("*.json")):
        # Skip sidecar files and metadata
        if spec_path.stem.endswith((".media", ".manifest", ".transform")):
            continue
        if spec_path.name in {"packages.json", "manifest.json"}:
            continue
        
        output_path = DIST_DIR / spec_path.name
        
        if minify_and_copy_spec(spec_path, output_path):
            success_count += 1
            total_original += spec_path.stat().st_size
            total_minified += output_path.stat().st_size
        else:
            fail_count += 1
    
    # Step 4: Copy sidecar files
    copy_sidecar_files()
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 Build Summary:")
    print(f"  ✅ Specs processed: {success_count}")
    if fail_count > 0:
        print(f"  ❌ Failed: {fail_count}")
    
    if total_original > 0:
        total_saved = total_original - total_minified
        reduction_pct = (total_saved / total_original * 100)
        print(f"\n  📦 Size reduction:")
        print(f"     Original: {total_original:,} bytes ({total_original/1024/1024:.1f} MB)")
        print(f"     Minified: {total_minified:,} bytes ({total_minified/1024/1024:.1f} MB)")
        print(f"     Saved: {total_saved:,} bytes ({reduction_pct:.1f}%)")
    
    print(f"\n  📂 Output directory: {DIST_DIR}")
    print("=" * 60)
    
    # Step 5: Verify dist structure
    print("\n🔍 Verifying dist structure:")
    spec_count = len(list(DIST_DIR.glob("*.json")))
    sidecar_count = len(list(DIST_DIR.glob("*.manifest.json"))) + \
                    len(list(DIST_DIR.glob("*.transform.json"))) + \
                    len(list(DIST_DIR.glob("*.media.json")))
    
    print(f"  📄 Main specs: {spec_count - sidecar_count}")
    print(f"  📎 Sidecar files: {sidecar_count}")
    
    if (spec_count - sidecar_count) > 0:
        print("\n✅ Production build completed successfully!")
        print("\n🎯 The server will automatically use these optimized specs from dist/")
        return 0
    else:
        print("\n❌ Build validation failed - no specs in dist!")
        return 1


if __name__ == "__main__":
    sys.exit(main())