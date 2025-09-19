from __future__ import annotations

from importlib import import_module
from typing import Any, Callable, Dict, List

PatchFn = Callable[[dict], tuple[bool, List[str]]]


def get_patches_for_namespace(namespace: str) -> List[PatchFn]:
    """Return a list of patch functions for a given namespace.

    Discovers a module in .build/spec_patches/patches/<Namespace>.py and reads
    its PATCHES list if present. Returns empty list if not found.
    """
    try:
        mod = import_module(f"spec_patches.patches.{namespace}")
    except Exception:
        return []

    patches = getattr(mod, "PATCHES", None)
    if isinstance(patches, list):
        # Filter to callables
        return [p for p in patches if callable(p)]  # type: ignore
    return []

