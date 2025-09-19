from __future__ import annotations

from typing import Any, Dict, List, Tuple

# Import safety defaults if available
try:
    from .safety_defaults import apply_safety_defaults
    SAFETY_DEFAULTS_AVAILABLE = True
except ImportError:
    SAFETY_DEFAULTS_AVAILABLE = False


def apply_common_transforms(spec: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Apply generic, idempotent cleanups that are safe across specs.

    This includes:
    - Server normalization
    - Empty description cleanup
    - Safety default overrides (if enabled)
    
    Currently conservative: we avoid heavy mutations since runtime already
    slims descriptions. Extend here with more policy transforms when needed.
    """
    changed = False
    notes: List[str] = []

    # Ensure servers is a list of objects with url only (strip descriptions)
    servers = spec.get("servers")
    if isinstance(servers, list):
        fixed: List[Dict[str, Any]] = []
        for srv in servers:
            if isinstance(srv, dict) and "url" in srv:
                url = srv["url"]
                if isinstance(url, str) and " (" in url:
                    url = url.split(" (")[0].strip()
                fixed.append({"url": url})
        if fixed and fixed != servers:
            spec["servers"] = fixed
            changed = True
            notes.append("normalized servers entries (url only)")

    # Normalize empty descriptions to None to help some clients
    paths = spec.get("paths") or {}
    if isinstance(paths, dict):
        for p, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for m, op in methods.items():
                if not isinstance(op, dict):
                    continue
                if op.get("description", None) == "":
                    op["description"] = None
                    changed = True
                    notes.append(f"cleared empty description on {m.upper()} {p}")

    # Apply safety defaults if available
    if SAFETY_DEFAULTS_AVAILABLE:
        safety_changed, safety_notes = apply_safety_defaults(spec)
        if safety_changed:
            changed = True
            notes.extend(safety_notes)

    return changed, notes

