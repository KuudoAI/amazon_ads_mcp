"""Safety and security default overrides for OpenAPI specs.

This module contains patches that enforce safer defaults across all specs,
following the principle of least privilege and secure-by-default patterns.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple


# Configuration for parameter defaults that should be overridden
SAFER_DEFAULTS = {
    # parameter_name: (unsafe_value, safe_value, reason)
    "accessLevel": ("edit", "view", "Least privilege: default to read-only access"),
    "includeDeleted": (True, False, "Don't include deleted items by default"),
    "includeArchived": (True, False, "Don't include archived items by default"),
    "autoApprove": (True, False, "Require explicit approval"),
    "skipValidation": (True, False, "Always validate by default"),
    "forceUpdate": (True, False, "Require explicit force flag"),
    "allowDuplicates": (True, False, "Prevent duplicates by default"),
}


def apply_safety_defaults(spec: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Apply safer default values to parameters across all operations.
    
    This function scans all operations in the spec and updates parameter
    defaults to safer values based on the SAFER_DEFAULTS configuration.
    
    Args:
        spec: The OpenAPI specification to patch
        
    Returns:
        Tuple of (changed: bool, notes: List[str])
    """
    notes: List[str] = []
    changed = False
    
    paths = spec.get("paths") or {}
    if not isinstance(paths, dict):
        return False, notes
    
    # Track changes by parameter
    changes_by_param: Dict[str, List[str]] = {}
    
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
            
        for method, operation in methods.items():
            if not isinstance(operation, dict):
                continue
                
            # Check parameters at operation level
            parameters = operation.get("parameters") or []
            if not isinstance(parameters, list):
                continue
                
            for param in parameters:
                if not isinstance(param, dict):
                    continue
                    
                param_name = param.get("name")
                if param_name in SAFER_DEFAULTS:
                    unsafe_val, safe_val, reason = SAFER_DEFAULTS[param_name]
                    
                    schema = param.get("schema") or {}
                    if not isinstance(schema, dict):
                        continue
                        
                    # Check if it has the unsafe default
                    if schema.get("default") == unsafe_val:
                        # Change to safer default
                        schema["default"] = safe_val
                        changed = True
                        
                        # Track the change
                        if param_name not in changes_by_param:
                            changes_by_param[param_name] = []
                        changes_by_param[param_name].append(f"{method.upper()} {path}")
    
    # Generate notes for all changes
    for param_name, operations in changes_by_param.items():
        unsafe_val, safe_val, reason = SAFER_DEFAULTS[param_name]
        notes.append(
            f"{param_name}: '{unsafe_val}' → '{safe_val}' ({reason}) in {len(operations)} operations"
        )
        # Optionally list specific operations if not too many
        if len(operations) <= 3:
            for op in operations:
                notes.append(f"  - {op}")
    
    return changed, notes


def enforce_required_headers(spec: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Ensure critical security headers are marked as required.
    
    This function ensures that important headers like API keys, tokens,
    and client IDs are properly marked as required in the spec.
    """
    notes: List[str] = []
    changed = False
    
    # Headers that should always be required
    REQUIRED_HEADERS = {
        "Amazon-Advertising-API-ClientId",
        "Amazon-Advertising-API-Scope",  # For profile-scoped operations
    }
    
    paths = spec.get("paths") or {}
    if not isinstance(paths, dict):
        return False, notes
    
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
            
        for method, operation in methods.items():
            if not isinstance(operation, dict):
                continue
                
            parameters = operation.get("parameters") or []
            
            for param in parameters:
                if not isinstance(param, dict):
                    continue
                    
                if (param.get("in") == "header" and 
                    param.get("name") in REQUIRED_HEADERS and
                    not param.get("required")):
                    
                    param["required"] = True
                    changed = True
                    notes.append(
                        f"Made header '{param['name']}' required in {method.upper()} {path}"
                    )
    
    return changed, notes


def add_safety_descriptions(spec: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Add or enhance descriptions for parameters with safety implications.
    
    This ensures users understand the security implications of certain parameters.
    """
    notes: List[str] = []
    changed = False
    
    # Additional descriptions to append for certain parameters
    SAFETY_DESCRIPTIONS = {
        "accessLevel": "\n⚠️ Security Note: 'edit' permission allows modification. Use 'view' when read-only access is sufficient.",
        "forceUpdate": "\n⚠️ Warning: This bypasses validation checks. Use with caution.",
        "skipValidation": "\n⚠️ Warning: Disabling validation may lead to data inconsistencies.",
    }
    
    paths = spec.get("paths") or {}
    if not isinstance(paths, dict):
        return False, notes
    
    updated_params = set()
    
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
            
        for method, operation in methods.items():
            if not isinstance(operation, dict):
                continue
                
            parameters = operation.get("parameters") or []
            
            for param in parameters:
                if not isinstance(param, dict):
                    continue
                    
                param_name = param.get("name")
                if param_name in SAFETY_DESCRIPTIONS:
                    current_desc = param.get("description", "")
                    safety_note = SAFETY_DESCRIPTIONS[param_name]
                    
                    # Only add if not already present
                    if safety_note not in current_desc:
                        param["description"] = current_desc + safety_note
                        changed = True
                        updated_params.add(param_name)
    
    if updated_params:
        notes.append(f"Added safety descriptions to: {', '.join(sorted(updated_params))}")
    
    return changed, notes