"""Targeted patches for AccountsProfiles OpenAPI spec.

This module contains patches specific to the AccountsProfiles namespace,
including default value overrides for safer API behavior.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple


def patch_access_level_defaults(spec: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Change accessLevel parameter defaults from 'edit' to 'view' for safety.
    
    The default 'edit' permission is too permissive. Defaulting to 'view'
    follows the principle of least privilege - users should explicitly
    request edit access when needed.
    """
    notes: List[str] = []
    changed = False
    
    paths = spec.get("paths") or {}
    if not isinstance(paths, dict):
        return False, notes
    
    # Track which operations we update
    updated_operations = []
    
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
            
        for method, operation in methods.items():
            if not isinstance(operation, dict):
                continue
                
            # Check parameters
            parameters = operation.get("parameters") or []
            if not isinstance(parameters, list):
                continue
                
            for param in parameters:
                if not isinstance(param, dict):
                    continue
                    
                # Look for accessLevel parameter
                if param.get("name") == "accessLevel" and param.get("in") == "query":
                    schema = param.get("schema") or {}
                    if not isinstance(schema, dict):
                        continue
                        
                    # Check if it has the unsafe default
                    if schema.get("default") == "edit":
                        # Change to safer default
                        schema["default"] = "view"
                        changed = True
                        updated_operations.append(f"{method.upper()} {path}")
    
    if changed:
        notes.append(
            f"accessLevel default changed from 'edit' to 'view' for: {', '.join(updated_operations)}"
        )
    
    return changed, notes


def patch_profile_validations(spec: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Add or enhance validation rules for profile operations.
    
    Ensures that critical profile operations have proper validation schemas.
    """
    notes: List[str] = []
    changed = False
    
    # This is a placeholder for additional validation patches
    # You can extend this to add required fields, patterns, etc.
    
    return changed, notes


# Expose patch list for registry
PATCHES = [
    patch_access_level_defaults,
    patch_profile_validations,
]