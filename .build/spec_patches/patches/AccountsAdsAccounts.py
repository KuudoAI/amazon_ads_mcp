from __future__ import annotations

from typing import Any, Dict, List, Tuple


def _get(d: Dict[str, Any], *keys: str) -> Any:
    cur: Any = d
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return None
        cur = cur[k]
    return cur


def patch_list_ads_accounts_response(spec: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Fix /adsAccounts/list 200 response schema shape.

    The generated spec marks the 200 response as a top-level array, but the
    actual API returns an object with an "adsAccounts" array property (and
    possibly pagination metadata). Adjust schema accordingly if needed.
    """
    notes: List[str] = []
    changed = False

    paths = spec.get("paths") or {}
    if not isinstance(paths, dict):
        return False, notes

    node = _get(paths, "/adsAccounts/list", "post", "responses", "200", "content")
    if not isinstance(node, dict):
        return False, notes

    # Accept either vendor-specific content type or any single content
    # We will iterate all content entries and fix those that are arrays.
    for ctype, content in list(node.items()):
        if not isinstance(content, dict):
            continue
        schema = content.get("schema")
        if not isinstance(schema, dict):
            continue
        if schema.get("type") == "array":
            # Replace with object containing adsAccounts: array
            new_schema = {
                "type": "object",
                "properties": {
                    "adsAccounts": {
                        "type": "array",
                        "items": {"type": "object"},
                        "description": "List of advertising accounts",
                    }
                },
                "additionalProperties": True,
                "description": "Response object containing adsAccounts array",
            }
            content["schema"] = new_schema
            changed = True
            notes.append(
                f"/adsAccounts/list 200 {ctype}: array -> object with adsAccounts[]"
            )

    return changed, notes


# Expose patch list for registry
PATCHES = [patch_list_ads_accounts_response]

