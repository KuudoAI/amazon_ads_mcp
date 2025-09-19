#!/usr/bin/env python3
"""
OpenAPI post-processor for amazon-ads-api-mcp

Downloads specs from config if needed, then runs common transforms and 
targeted hotfix patches against specs. Supports dry-run, diff, and in-place fixes.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import urllib.request
import yaml
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[2]
RESOURCES_DIR = ROOT / "openapi" / "resources"
CONFIG_FILE = ROOT / ".build" / "config" / "amazon_ads_openapi.json"

# Utilities and patches
sys.path.insert(0, str((ROOT / ".build").resolve()))

from spec_utils.io import load_json, save_json  # type: ignore
from spec_patches.common import apply_common_transforms  # type: ignore
from spec_patches.registry import get_patches_for_namespace  # type: ignore


def extract_operations_metadata(spec: Dict[str, Any], namespace: str) -> List[Dict[str, Any]]:
    """Extract operation metadata from OpenAPI spec for manifest generation."""
    operations = []
    paths = spec.get("paths", {})
    
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, operation in methods.items():
            if method in ["parameters", "servers", "$ref"]:
                continue
            if not isinstance(operation, dict):
                continue
            
            op_id = operation.get("operationId")
            if not op_id:
                continue
            
            # Extract operation info
            op_info = {
                "operationId": op_id,
                "method": method.upper(),
                "path": path,
                "preferred_name": f"{namespace}_{op_id}",
                "complexity": {
                    "parameters": len(operation.get("parameters", [])),
                    "has_body": "requestBody" in operation,
                    "responses": len(operation.get("responses", {}))
                }
            }
            operations.append(op_info)
    
    return operations


def generate_manifest_sidecar(spec_path: Path, spec: Dict[str, Any]) -> bool:
    """Generate .manifest.json sidecar file for a spec."""
    namespace = spec_path.stem
    manifest_path = spec_path.with_suffix(".manifest.json")
    
    operations = extract_operations_metadata(spec, namespace)
    if not operations:
        return False
    
    manifest = {
        "version": "1.0",
        "generated": "auto",
        "namespace": namespace,
        "tools": operations
    }
    
    try:
        with open(manifest_path, 'w', encoding='utf-8') as f:
            json.dump(manifest, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"Failed to write manifest for {namespace}: {e}")
        return False


def generate_transform_sidecar(spec_path: Path, spec: Dict[str, Any]) -> bool:
    """Generate .transform.json sidecar file with default transformations."""
    namespace = spec_path.stem
    transform_path = spec_path.with_suffix(".transform.json")
    
    # Build transforms for each operation
    transforms = []
    paths = spec.get("paths", {})
    
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, operation in methods.items():
            if method in ["parameters", "servers", "$ref"]:
                continue
            if not isinstance(operation, dict):
                continue
            
            op_id = operation.get("operationId")
            if not op_id:
                continue
            
            # Create a basic transform rule
            transform_rule = {
                "match": {
                    "operationId": op_id
                }
            }
            
            # Add pagination if common patterns detected
            if any(param.get("name") in ["nextToken", "pageToken", "cursor", "offset"] 
                   for param in operation.get("parameters", []) 
                   if isinstance(param, dict)):
                transform_rule["pagination"] = {
                    "param_name": "nextToken",
                    "response_key": "nextToken",
                    "all_pages": False,
                    "limit_param": "maxResults",
                    "default_limit": 100
                }
            
            # Add output transforms for large responses
            transform_rule["output_transform"] = {
                "sample_n": 10,
                "artifact_threshold_bytes": 10240
            }
            
            transforms.append(transform_rule)
    
    if not transforms:
        return False
    
    transform = {
        "version": "1.0",
        "generated": "auto",
        "namespace": namespace,
        "tools": transforms
    }
    
    try:
        with open(transform_path, 'w', encoding='utf-8') as f:
            json.dump(transform, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"Failed to write transform for {namespace}: {e}")
        return False


def generate_media_sidecar(spec_path: Path, spec: Dict[str, Any]) -> bool:
    """Generate .media.json sidecar file for content type mappings."""
    namespace = spec_path.stem
    media_path = spec_path.parent / f"{namespace}.media.json"
    
    # Extract unique content types from the spec
    content_types = set()
    paths = spec.get("paths", {})
    
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, operation in methods.items():
            if not isinstance(operation, dict):
                continue
            
            # Check request body content types
            request_body = operation.get("requestBody")
            if request_body and isinstance(request_body, dict):
                content = request_body.get("content", {})
                content_types.update(content.keys())
            
            # Check response content types
            responses = operation.get("responses", {})
            for status, response in responses.items():
                if isinstance(response, dict):
                    content = response.get("content", {})
                    content_types.update(content.keys())
    
    if not content_types:
        return False
    
    media = {
        "version": "1.0",
        "namespace": namespace,
        "content_types": sorted(list(content_types))
    }
    
    try:
        with open(media_path, 'w', encoding='utf-8') as f:
            json.dump(media, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"Failed to write media file for {namespace}: {e}")
        return False


def generate_packages_json(process_dir: Path, config: Dict[str, Any]) -> bool:
    """Generate packages.json file with full structure from config."""
    packages_path = process_dir / "packages.json"
    
    # Extract namespace mappings from config
    downloads = config.get("openapiDownloads", [])
    
    # Build the mappings from config
    prefixes = {}  # namespace -> prefix
    packages = {}  # package -> namespace
    aliases = {}   # package -> namespace (same as packages for compatibility)
    
    for item in downloads:
        if item.get("active") != "true":
            continue
        
        namespace = item.get("namespace")
        prefix = item.get("prefix")
        package = item.get("package")
        
        if namespace and prefix and package:
            # Use the authoritative mappings from config
            prefixes[namespace] = prefix
            packages[package] = namespace
            aliases[package] = namespace
    
    # Define groups based on package names (using actual package names from config)
    groups = {
        "core": ["profiles", "exports-snapshots"],
        "sponsored": ["sponsored-products", "sponsored-brands-v3", "sponsored-brands-v4", "sponsored-display"],
        "amc": ["amc-administration", "amc-workflow", "amc-rule-audience", "amc-ad-audience"],
        "dsp": ["dsp-measurement", "dsp-advertisers", "dsp-audiences", "dsp-conversions", "dsp-target-kpi-recommendations"],
        "reporting": ["reporting-version-3", "brand-metrics", "stores-analytics", "exports-snapshots", "marketing-mix-modeling"]
    }
    
    # Build the full manifest structure
    manifest = {
        "version": "1.0",
        "generated": "auto",
        "packages": packages,
        "prefixes": prefixes,
        "aliases": aliases,
        "groups": groups,
        "defaults": []
    }
    
    try:
        with open(packages_path, 'w', encoding='utf-8') as f:
            json.dump(manifest, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"Failed to write packages.json: {e}")
        return False


def download_specs_from_config(target_dir: Path) -> bool:
    """Download OpenAPI specs from URLs in config file to target directory.
    
    Returns True if successful, False otherwise.
    """
    if not CONFIG_FILE.exists():
        print(f"Config file not found: {CONFIG_FILE}")
        return False
    
    try:
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
    except Exception as e:
        print(f"Failed to load config: {e}")
        return False
    
    downloads = config.get("openapiDownloads", [])
    if not downloads:
        print("No download URLs found in config")
        return False
    
    print(f"Found {len(downloads)} specs to download")
    target_dir.mkdir(parents=True, exist_ok=True)
    
    success_count = 0
    for item in downloads:
        if item.get("active") != "true":
            continue
            
        namespace = item.get("namespace")
        url = item.get("downloadLink")
        
        if not namespace or not url:
            continue
        
        # Determine file extension from URL
        if url.endswith('.yaml') or url.endswith('.yml'):
            temp_ext = '.yaml'
            final_ext = '.json'
        else:
            temp_ext = '.json'
            final_ext = '.json'
        
        temp_file = target_dir / f"{namespace}{temp_ext}"
        final_file = target_dir / f"{namespace}{final_ext}"
        
        print(f"  Downloading {namespace} from {url[:50]}...")
        
        try:
            # Download the file
            with urllib.request.urlopen(url, timeout=30) as response:
                content = response.read()
            
            # Save to temp file
            with open(temp_file, 'wb') as f:
                f.write(content)
            
            # Convert YAML to JSON if needed
            if temp_ext == '.yaml':
                try:
                    with open(temp_file, 'r', encoding='utf-8') as f:
                        data = yaml.safe_load(f)
                    with open(final_file, 'w', encoding='utf-8') as f:
                        json.dump(data, f, indent=2, ensure_ascii=False)
                    temp_file.unlink()  # Remove yaml file
                    print(f"    ✓ {namespace} (converted from YAML)")
                except Exception as e:
                    print(f"    ✗ {namespace}: Failed to convert YAML: {e}")
                    continue
            else:
                # Validate JSON
                try:
                    with open(temp_file, 'r', encoding='utf-8') as f:
                        json.load(f)
                    print(f"    ✓ {namespace}")
                except json.JSONDecodeError as e:
                    print(f"    ✗ {namespace}: Invalid JSON: {e}")
                    temp_file.unlink()
                    continue
            
            success_count += 1
            
        except Exception as e:
            print(f"    ✗ {namespace}: {e}")
            if temp_file.exists():
                temp_file.unlink()
    
    print(f"Downloaded {success_count}/{len(downloads)} specs successfully")
    
    # Generate packages.json
    if success_count > 0:
        print("\nGenerating packages.json...")
        if generate_packages_json(target_dir, config):
            print("  ✓ packages.json created")
        else:
            print("  ✗ Failed to create packages.json")
    
    return success_count > 0


def _detect_namespace(path: Path) -> str:
    return path.stem


def validate_minimal(spec: Dict[str, Any]) -> List[str]:
    """Return a list of validation warnings (no exception).

    This is intentionally light-weight to avoid blocking CI for cosmetic issues.
    """
    warnings: List[str] = []
    if not isinstance(spec, dict) or "openapi" not in spec:
        warnings.append("Missing top-level 'openapi' key")
        return warnings

    paths = spec.get("paths") or {}
    if not isinstance(paths, dict) or not paths:
        warnings.append("Spec has no paths")
        return warnings

    # Ensure each operation has at least one 2xx response
    for p, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for m, op in methods.items():
            if not isinstance(op, dict):
                continue
            responses = op.get("responses") or {}
            if not isinstance(responses, dict):
                warnings.append(f"{m.upper()} {p}: responses not an object")
                continue
            if not any(str(k).startswith("2") for k in responses.keys()):
                warnings.append(f"{m.upper()} {p}: has no 2xx response declared")
    return warnings


def apply_pipeline(spec: Dict[str, Any], namespace: str) -> Tuple[Dict[str, Any], List[str]]:
    """Apply common transforms and namespace-specific patches.

    Returns the possibly-modified spec and a list of human-readable change notes.
    """
    notes: List[str] = []

    changed_common, note_common = apply_common_transforms(spec)
    if note_common:
        notes.extend(note_common)

    patches = get_patches_for_namespace(namespace)
    for patch_fn in patches:
        changed, patch_notes = patch_fn(spec)
        if patch_notes:
            notes.extend(patch_notes)

    return spec, notes


def dump_diff(original: Dict[str, Any], updated: Dict[str, Any]) -> str:
    """Return a simple textual diff (JSON-level) for quick inspection."""
    try:
        from difflib import unified_diff

        a = json.dumps(original, indent=2, sort_keys=True, ensure_ascii=False).splitlines(
            True
        )
        b = json.dumps(updated, indent=2, sort_keys=True, ensure_ascii=False).splitlines(
            True
        )
        return "".join(unified_diff(a, b, fromfile="original", tofile="updated"))
    except Exception:
        return "(diff unavailable)"


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Process OpenAPI specs with patches")
    ap.add_argument(
        "--fix", action="store_true", help="Write changes back to files"
    )
    ap.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero if any file would change (no writes)",
    )
    ap.add_argument(
        "--diff", action="store_true", help="Print unified diff for changes"
    )
    ap.add_argument(
        "--only",
        metavar="NAMESPACE",
        help="Process only files whose stem matches this namespace",
    )
    ap.add_argument(
        "--skip-download",
        action="store_true",
        help="Skip downloading specs even if directory is empty",
    )
    ap.add_argument(
        "--use-temp",
        action="store_true",
        help="Download to temp directory instead of resources",
    )
    args = ap.parse_args(argv)

    # Determine where to process specs from
    if args.use_temp:
        # Use a temporary directory for processing
        temp_dir = Path(tempfile.mkdtemp(prefix="openapi_specs_"))
        print(f"Using temporary directory: {temp_dir}")
        process_dir = temp_dir
        
        # Always download to temp directory
        print("\nDownloading OpenAPI specifications from config...")
        if not download_specs_from_config(temp_dir):
            print("Failed to download specs")
            return 1
    else:
        # Use the normal resources directory
        process_dir = RESOURCES_DIR
        
        # Check if we need to download specs
        if not RESOURCES_DIR.exists() or not list(RESOURCES_DIR.glob("*.json")):
            if args.skip_download:
                print(f"No specs found at {RESOURCES_DIR} (download skipped)")
                return 0
            
            print(f"No specs found at {RESOURCES_DIR}")
            print("Downloading OpenAPI specifications from config...")
            
            # Create resources directory
            RESOURCES_DIR.mkdir(parents=True, exist_ok=True)
            
            # Download specs
            if not download_specs_from_config(RESOURCES_DIR):
                print("Failed to download specs")
                print("Please check your internet connection and the config file")
                return 1

    # Process specs
    print(f"\nProcessing specs from {process_dir}")
    changed_any = False
    
    # Load config for packages.json generation
    config = None
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
        except:
            pass
    
    for spec_path in sorted(process_dir.glob("*.json")):
        # Skip sidecar files
        if spec_path.stem.endswith((".media", ".manifest", ".transform")):
            continue
        if spec_path.name in {"packages.json", "manifest.json"}:
            continue

        ns = _detect_namespace(spec_path)
        if args.only and ns != args.only:
            continue

        try:
            original = load_json(spec_path)
        except Exception as e:
            print(f"Failed to load {spec_path}: {e}")
            continue

        # Work on a deep copy to compare later
        import copy

        before = copy.deepcopy(original)
        updated, notes = apply_pipeline(original, ns)

        # Validation warnings (non-fatal)
        warnings = validate_minimal(updated)
        for w in warnings:
            print(f"[warn] {spec_path.name}: {w}")
        
        # Generate sidecar files
        if args.fix or args.use_temp:
            # Determine output directory
            if args.use_temp:
                sidecar_dir = RESOURCES_DIR
                sidecar_dir.mkdir(parents=True, exist_ok=True)
            else:
                sidecar_dir = spec_path.parent
            
            # Create sidecar spec path
            sidecar_spec_path = sidecar_dir / spec_path.name
            
            # Generate manifest sidecar
            if generate_manifest_sidecar(sidecar_spec_path, updated):
                print(f"  → Generated {ns}.manifest.json")
            
            # Generate transform sidecar
            if generate_transform_sidecar(sidecar_spec_path, updated):
                print(f"  → Generated {ns}.transform.json")
            
            # Generate media sidecar
            if generate_media_sidecar(sidecar_spec_path, updated):
                print(f"  → Generated {ns}.media.json")

        if before != updated:
            changed_any = True
            print(f"[change] {spec_path.name} ({ns})")
            for n in notes:
                print(f"  - {n}")
            if args.diff:
                print(dump_diff(before, updated))
            if args.fix:
                try:
                    # Write to the resources directory even if processing from temp
                    if args.use_temp:
                        output_path = RESOURCES_DIR / spec_path.name
                        RESOURCES_DIR.mkdir(parents=True, exist_ok=True)
                    else:
                        output_path = spec_path
                    save_json(output_path, updated)
                except Exception as e:
                    print(f"Failed to write {output_path}: {e}")
    
    # Generate packages.json if we have config and are fixing/saving
    if config and (args.fix or args.use_temp):
        output_dir = RESOURCES_DIR if args.use_temp else process_dir
        output_dir.mkdir(parents=True, exist_ok=True)
        print("\nGenerating packages.json...")
        if generate_packages_json(output_dir, config):
            print(f"  ✓ packages.json created at {output_dir / 'packages.json'}")
        else:
            print("  ✗ Failed to create packages.json")
    
    # Cleanup temp directory if used
    if args.use_temp:
        import shutil
        try:
            shutil.rmtree(temp_dir)
        except:
            pass

    if args.check and changed_any:
        return 1
    return 0


if __name__ == "__main__":
    # Check for required modules
    try:
        import yaml
    except ImportError:
        print("PyYAML is required for downloading specs. Installing...")
        subprocess.run([sys.executable, "-m", "pip", "install", "pyyaml"], check=True)
        import yaml
    
    raise SystemExit(main())