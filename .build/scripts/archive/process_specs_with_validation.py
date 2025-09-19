#!/usr/bin/env python3
"""
Process OpenAPI specs with namespace isolation and validation.
Maintains schema integrity by using directory structure as namespaces.
"""

import json
import os
from pathlib import Path
from typing import Dict, Any, List, Set
import hashlib
from collections import defaultdict

class SpecProcessor:
    def __init__(self, source_dir: Path, output_dir: Path):
        self.source_dir = source_dir
        self.output_dir = output_dir
        self.processed_specs = {}
        self.original_schemas = {}  # Track original schemas for validation
        self.namespace_schemas = defaultdict(dict)  # Namespace -> schema name -> schema
        self.validation_report = []
        
    def process_all_specs(self):
        """Process all specs with step-wise validation."""
        print("="*60)
        print("Step-wise OpenAPI Spec Processing with Namespace Isolation")
        print("="*60)
        
        # Step 1: Process each file individually with namespace
        all_files = list(self.source_dir.rglob("*.json"))
        print(f"\nFound {len(all_files)} spec files to process")
        
        for spec_file in all_files:
            namespace = self._get_namespace(spec_file)
            print(f"\n📁 Processing: {spec_file.relative_to(self.source_dir)}")
            print(f"   Namespace: {namespace}")
            
            # Process single file
            processed = self._process_single_file(spec_file, namespace)
            
            # Validate against original
            if self._validate_against_original(spec_file, processed, namespace):
                print(f"   ✅ Validation passed")
                self.processed_specs[namespace] = processed
            else:
                print(f"   ❌ Validation failed - see report")
        
        # Step 2: Merge with namespace isolation
        print("\n" + "="*60)
        print("Merging specs with namespace isolation")
        merged = self._merge_with_namespaces()
        
        # Step 3: Final validation
        print("\n" + "="*60)
        print("Running final validation")
        self._final_validation(merged)
        
        # Debug: Check what specs were processed
        print("\n" + "="*60)
        print("Debug: Processed specs summary")
        for namespace in self.processed_specs:
            spec = self.processed_specs[namespace]
            schema_count = 0
            if "components" in spec and "schemas" in spec["components"]:
                schema_count = len(spec["components"]["schemas"])
            print(f"  {namespace}: {schema_count} schemas")
        
        # Step 4: Save results
        self._save_results(merged)
        
        # Print validation report
        self._print_validation_report()
    
    def _get_namespace(self, spec_file: Path) -> str:
        """Get namespace from file path structure including filename."""
        # Remove source_dir to get relative path
        relative_path = spec_file.relative_to(self.source_dir)
        
        # Include directory structure AND filename (without extension) as namespace
        # e.g., accounts/portfolios.json -> accounts_portfolios
        # e.g., campaign_management/campaigns.json -> campaign_management_campaigns
        parts = list(relative_path.parts[:-1])  # Directory parts
        filename_without_ext = relative_path.stem  # Filename without .json
        
        # Combine directory and filename for unique namespace
        if parts:
            namespace_parts = parts + [filename_without_ext]
        else:
            namespace_parts = [filename_without_ext]
        
        return "_".join(namespace_parts)
    
    def _process_single_file(self, spec_file: Path, namespace: str) -> Dict:
        """Process a single OpenAPI spec file."""
        with open(spec_file) as f:
            spec = json.load(f)
        
        # Store original schemas for validation
        if "components" in spec and "schemas" in spec["components"]:
            for schema_name, schema_def in spec["components"]["schemas"].items():
                # Create namespaced version for tracking
                original_key = f"{namespace}::{schema_name}"
                self.original_schemas[original_key] = {
                    "definition": schema_def.copy(),
                    "source_file": str(spec_file),
                    "required_fields": schema_def.get("required", [])
                }
                
                # Store in namespace
                self.namespace_schemas[namespace][schema_name] = schema_def.copy()
        
        return spec
    
    def _validate_against_original(self, spec_file: Path, processed: Dict, namespace: str) -> bool:
        """Validate processed spec against original."""
        validation_passed = True
        
        # Load original
        with open(spec_file) as f:
            original = json.load(f)
        
        # Check paths are preserved
        if "paths" in original:
            for path, path_def in original["paths"].items():
                if path not in processed.get("paths", {}):
                    self.validation_report.append({
                        "type": "error",
                        "file": str(spec_file),
                        "message": f"Path {path} missing in processed spec"
                    })
                    validation_passed = False
        
        # Check schemas haven't been contaminated
        if "components" in processed and "schemas" in processed["components"]:
            for schema_name, schema_def in processed["components"]["schemas"].items():
                original_key = f"{namespace}::{schema_name}"
                
                if original_key in self.original_schemas:
                    original_schema = self.original_schemas[original_key]["definition"]
                    
                    # Check required fields match
                    original_required = set(original_schema.get("required", []))
                    processed_required = set(schema_def.get("required", []))
                    
                    if original_required != processed_required:
                        self.validation_report.append({
                            "type": "warning",
                            "file": str(spec_file),
                            "schema": schema_name,
                            "message": f"Required fields mismatch. Original: {original_required}, Processed: {processed_required}"
                        })
                    
                    # Check properties match
                    original_props = set(original_schema.get("properties", {}).keys())
                    processed_props = set(schema_def.get("properties", {}).keys())
                    
                    extra_props = processed_props - original_props
                    if extra_props:
                        self.validation_report.append({
                            "type": "error",
                            "file": str(spec_file),
                            "schema": schema_name,
                            "message": f"Extra properties added: {extra_props}"
                        })
                        validation_passed = False
                    
                    missing_props = original_props - processed_props
                    if missing_props:
                        self.validation_report.append({
                            "type": "error",
                            "file": str(spec_file),
                            "schema": schema_name,
                            "message": f"Properties missing: {missing_props}"
                        })
                        validation_passed = False
        
        return validation_passed
    
    def _merge_with_namespaces(self) -> Dict:
        """Merge specs while maintaining namespace isolation."""
        merged = {
            "openapi": "3.0.1",
            "info": {
                "title": "Amazon Ads API - Merged",
                "version": "1.0.0"
            },
            "paths": {},
            "components": {
                "schemas": {},
                "parameters": {},
                "responses": {}
            }
        }
        
        # Track schema name collisions
        schema_sources = defaultdict(list)
        
        for namespace, spec in self.processed_specs.items():
            print(f"\nMerging namespace: {namespace}")
            
            # Merge paths
            if "paths" in spec:
                for path, path_def in spec["paths"].items():
                    if path in merged["paths"]:
                        self.validation_report.append({
                            "type": "warning",
                            "message": f"Path collision: {path} exists in multiple namespaces"
                        })
                    merged["paths"][path] = path_def
            
            # Merge schemas with ALWAYS namespaced approach
            if "components" in spec and "schemas" in spec["components"]:
                for schema_name, schema_def in spec["components"]["schemas"].items():
                    # Always use namespaced version for clarity and isolation
                    namespaced_name = f"{namespace}_{schema_name}"
                    
                    # Copy the schema and update internal references
                    updated_schema = schema_def.copy()
                    self._update_all_refs(updated_schema, namespace)
                    
                    # Add the schema with namespace
                    merged["components"]["schemas"][namespaced_name] = updated_schema
                    
                    # Track for reporting
                    schema_sources[schema_name].append(namespace)
            
            # Merge parameters with namespace
            if "components" in spec and "parameters" in spec["components"]:
                for param_name, param_def in spec["components"]["parameters"].items():
                    namespaced_name = f"{namespace}_{param_name}"
                    # Copy and update internal references
                    updated_param = param_def.copy()
                    self._update_all_refs(updated_param, namespace)
                    merged["components"]["parameters"][namespaced_name] = updated_param
            
            # Merge responses with namespace  
            if "components" in spec and "responses" in spec["components"]:
                for resp_name, resp_def in spec["components"]["responses"].items():
                    namespaced_name = f"{namespace}_{resp_name}"
                    # Copy and update internal references
                    updated_resp = resp_def.copy()
                    self._update_all_refs(updated_resp, namespace)
                    merged["components"]["responses"][namespaced_name] = updated_resp
            
            # Update all references in paths to use namespaced schemas
            if "paths" in spec:
                for path in spec["paths"].keys():
                    if path in merged["paths"]:
                        # Update the path definition to use namespaced schemas
                        self._update_all_refs(merged["paths"][path], namespace)
        
        # Report on collisions
        collisions = {name: sources for name, sources in schema_sources.items() 
                     if len(sources) > 1}
        if collisions:
            print(f"\n⚠️  Found {len(collisions)} schema name collisions:")
            for name, sources in collisions.items():
                print(f"   {name}: {', '.join(sources)}")
                self.validation_report.append({
                    "type": "info",
                    "message": f"Schema {name} appears in namespaces: {', '.join(sources)}"
                })
        
        return merged
    
    def _update_all_refs(self, obj: Any, namespace: str):
        """Update all references to use namespaced versions."""
        if isinstance(obj, dict):
            if "$ref" in obj and isinstance(obj["$ref"], str):
                ref = obj["$ref"]
                # Handle schema references
                if ref.startswith("#/components/schemas/"):
                    schema_name = ref.split("/")[-1]
                    # Don't double-namespace if already namespaced
                    if not schema_name.startswith(f"{namespace}_"):
                        obj["$ref"] = f"#/components/schemas/{namespace}_{schema_name}"
                # Handle parameter references
                elif ref.startswith("#/components/parameters/"):
                    param_name = ref.split("/")[-1]
                    if not param_name.startswith(f"{namespace}_"):
                        obj["$ref"] = f"#/components/parameters/{namespace}_{param_name}"
                # Handle response references
                elif ref.startswith("#/components/responses/"):
                    resp_name = ref.split("/")[-1]
                    if not resp_name.startswith(f"{namespace}_"):
                        obj["$ref"] = f"#/components/responses/{namespace}_{resp_name}"
            
            for value in obj.values():
                self._update_all_refs(value, namespace)
        elif isinstance(obj, list):
            for item in obj:
                self._update_all_refs(item, namespace)
    
    def _final_validation(self, merged: Dict):
        """Run final validation on merged spec."""
        print("\nFinal validation checks:")
        
        # Check all schema references are resolvable
        all_refs = self._find_all_refs(merged)
        schemas = set(merged.get("components", {}).get("schemas", {}).keys())
        
        unresolved = set()
        for ref in all_refs:
            if ref.startswith("#/components/schemas/"):
                schema_name = ref.split("/")[-1]
                if schema_name not in schemas:
                    unresolved.add(schema_name)
        
        if unresolved:
            print(f"  ❌ Unresolved schema references: {unresolved}")
            for ref in unresolved:
                self.validation_report.append({
                    "type": "error",
                    "message": f"Unresolved schema reference: {ref}"
                })
        else:
            print(f"  ✅ All {len(all_refs)} schema references are resolvable")
        
        # Check for contaminated schemas (e.g., Portfolio with marketplaceScope)
        print("\nChecking for schema contamination:")
        contamination_found = False
        
        for namespace, schemas in self.namespace_schemas.items():
            for schema_name, original_def in schemas.items():
                # Check the namespaced version in merged spec
                namespaced_name = f"{namespace}_{schema_name}"
                merged_schema = merged["components"]["schemas"].get(namespaced_name)
                if merged_schema:
                    original_props = set(original_def.get("properties", {}).keys())
                    merged_props = set(merged_schema.get("properties", {}).keys())
                    
                    extra_props = merged_props - original_props
                    if extra_props:
                        print(f"  ❌ {namespaced_name} has extra properties: {extra_props}")
                        contamination_found = True
                        self.validation_report.append({
                            "type": "error",
                            "namespace": namespace,
                            "schema": schema_name,
                            "message": f"Schema contaminated with extra properties: {extra_props}"
                        })
        
        if not contamination_found:
            print("  ✅ No schema contamination detected")
    
    def _find_all_refs(self, obj: Any, refs: Set[str] = None) -> Set[str]:
        """Find all $ref values in an object."""
        if refs is None:
            refs = set()
        
        if isinstance(obj, dict):
            if "$ref" in obj:
                refs.add(obj["$ref"])
            for value in obj.values():
                self._find_all_refs(value, refs)
        elif isinstance(obj, list):
            for item in obj:
                self._find_all_refs(item, refs)
        
        return refs
    
    def _save_results(self, merged: Dict):
        """Save processed results."""
        output_file = self.output_dir / "merged_with_namespaces.json"
        
        print(f"\nSaving merged spec to {output_file}")
        with open(output_file, "w") as f:
            json.dump(merged, f, indent=2)
        
        size_mb = output_file.stat().st_size / 1024 / 1024
        print(f"  Size: {size_mb:.2f}MB")
        
        # Save validation report
        report_file = self.output_dir / "validation_report.json"
        with open(report_file, "w") as f:
            json.dump(self.validation_report, f, indent=2)
        print(f"  Validation report: {report_file}")
    
    def _print_validation_report(self):
        """Print validation report summary."""
        print("\n" + "="*60)
        print("Validation Report Summary")
        print("="*60)
        
        errors = [r for r in self.validation_report if r["type"] == "error"]
        warnings = [r for r in self.validation_report if r["type"] == "warning"]
        info = [r for r in self.validation_report if r["type"] == "info"]
        
        print(f"Errors: {len(errors)}")
        print(f"Warnings: {len(warnings)}")
        print(f"Info: {len(info)}")
        
        if errors:
            print("\nErrors (first 5):")
            for error in errors[:5]:
                print(f"  - {error['message']}")
        
        if warnings:
            print("\nWarnings (first 5):")
            for warning in warnings[:5]:
                print(f"  - {warning['message']}")


def main():
    """Main entry point."""
    source_dir = Path("/Users/thomas/Github/amazon-ad-api-mcp/openapi/amazon_ads_apis")
    output_dir = Path("/Users/thomas/Github/amazon-ad-api-mcp/openapi")
    
    if not source_dir.exists():
        print(f"❌ Source directory not found: {source_dir}")
        return
    
    output_dir.mkdir(exist_ok=True)
    
    processor = SpecProcessor(source_dir, output_dir)
    processor.process_all_specs()


if __name__ == "__main__":
    main()