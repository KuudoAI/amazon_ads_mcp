#!/usr/bin/env python3
"""
Remove auth header parameters/properties from Amazon Ads OpenAPI specs.

Why:
- Prevents tools/LLMs from passing auth headers as API params
- Ensures a single source of truth: your auth layer injects headers
- Eliminates "conflicting clientId headers" and mysterious 400s

What it removes (case/sep-insensitive):
  - Amazon-Advertising-API-ClientId
  - Amazon-Ads-ClientId
  - Amazon-Advertising-API-Scope
  - Amazon-Ads-AccountId
…including inline operation params, $ref'd component params, and any stray
schema properties/requireds that match these names.

Outputs are deterministic (stable JSON, sorted keys).
Writes `<name>.clean.json` by default, or in-place with `--in-place`.

Usage:
  python scripts/remove_auth_params.py --in openapi/resources --recursive
  python scripts/remove_auth_params.py --in openapi/resources/spec.json
  python scripts/remove_auth_params.py --in openapi/resources --in-place --recursive
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# ------------------------------ config ----------------------------------- #

AUTH_HEADER_NAMES = (
    "Amazon-Advertising-API-ClientId",
    "Amazon-Ads-ClientId",
    "Amazon-Advertising-API-Scope",
    "Amazon-Ads-AccountId",
)

# Match header names forgivingly: case-insensitive, dashes/underscores/spaces equivalent
def _norm_header_name(name: str) -> str:
    return re.sub(r"[-_\s]", "", (name or "").strip().lower())

AUTH_MATCHES: Set[str] = {_norm_header_name(n) for n in AUTH_HEADER_NAMES}

# ------------------------------ utils ------------------------------------ #

def stable_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, indent=2, ensure_ascii=False)

def _json_load(p: Path) -> dict:
    with p.open("r", encoding="utf-8") as f:
        return json.load(f)

def _json_save(p: Path, data: dict) -> None:
    text = stable_json(data)
    if p.exists():
        old = p.read_text("utf-8")
        if old == text:
            return
    p.write_text(text, encoding="utf-8")

def _is_auth_header_param(param_obj: dict) -> bool:
    if not isinstance(param_obj, dict):
        return False
    if str(param_obj.get("in", "")).lower() != "header":
        return False
    name = str(param_obj.get("name", ""))
    return _norm_header_name(name) in AUTH_MATCHES

def _collect_removed_param_refs(spec: dict, is_auth_header=lambda p: _is_auth_header_param(p)) -> Set[str]:
    """
    Returns set like {'#/components/parameters/ClientIdHeader', ...} for params to remove.
    """
    removed: Set[str] = set()
    comps = (spec.get("components") or {}).get("parameters") or {}
    for key, param in list(comps.items()):
        if is_auth_header(param):
            removed.add(f"#/components/parameters/{key}")
    return removed

def _remove_from_required(required: Any, prop_name: str) -> Any:
    if isinstance(required, list):
        return [x for x in required if x != prop_name]
    return required

def _strip_auth_schema_props(schema: Any, removed_counter: Dict[str, int]) -> Any:
    """
    Remove properties in schemas that look like auth headers (rare but possible if specs embed them).
    """
    if isinstance(schema, dict):
        props = schema.get("properties")
        if isinstance(props, dict):
            to_del = []
            for prop_name in list(props.keys()):
                if _norm_header_name(prop_name) in AUTH_MATCHES:
                    to_del.append(prop_name)
            for prop_name in to_del:
                props.pop(prop_name, None)
                removed_counter["schema_properties"] += 1
                if "required" in schema:
                    schema["required"] = _remove_from_required(schema["required"], prop_name)

        # Recurse through nested schemas
        for k, v in list(schema.items()):
            schema[k] = _strip_auth_schema_props(v, removed_counter)
    elif isinstance(schema, list):
        for i, v in enumerate(schema):
            schema[i] = _strip_auth_schema_props(v, removed_counter)
    return schema

# ------------------------------ core ------------------------------------- #

def clean_spec(spec: dict) -> Tuple[dict, Dict[str, int]]:
    """
    Returns (cleaned_spec, stats)
    """
    stats = {
        "op_inline_params_removed": 0,
        "op_ref_params_removed": 0,
        "component_params_removed": 0,
        "schema_properties_removed": 0,
    }

    # 1) Identify component parameter refs to remove
    removed_param_refs = _collect_removed_param_refs(spec)

    # 2) Strip operation-level params (inline & $ref to removed)
    paths = spec.get("paths", {}) or {}
    for path, ops in list(paths.items()):
        if not isinstance(ops, dict):
            continue
        for method, op in list(ops.items()):
            if not isinstance(op, dict):
                continue
            params = op.get("parameters")
            if not isinstance(params, list) or not params:
                continue

            new_params = []
            for p in params:
                if isinstance(p, dict) and "$ref" in p:
                    ref = p.get("$ref")
                    if isinstance(ref, str) and ref in removed_param_refs:
                        stats["op_ref_params_removed"] += 1
                        continue
                    # keep other refs
                    new_params.append(p)
                    continue

                if _is_auth_header_param(p):
                    stats["op_inline_params_removed"] += 1
                    continue

                new_params.append(p)

            if new_params:
                op["parameters"] = new_params
            else:
                op.pop("parameters", None)

    # 3) Remove the auth header component parameters themselves
    comps = spec.get("components") or {}
    comp_params = comps.get("parameters") or {}
    for key, param in list(comp_params.items()):
        if _is_auth_header_param(param):
            comp_params.pop(key, None)
            stats["component_params_removed"] += 1

    if comp_params:
        comps["parameters"] = comp_params
    elif "parameters" in comps:
        # Leave an empty dict to be safe (OpenAPI allows empty components subsections)
        comps["parameters"] = {}

    spec["components"] = comps

    # 4) Optional: scrub any stray schema properties that look like headers
    #    (defensive; keeps behavior aligned with your MD doc)
    if "components" in spec and "schemas" in spec["components"]:
        schemas = spec["components"]["schemas"]
        for name, schema in list(schemas.items()):
            schemas[name] = _strip_auth_schema_props(schema, {"schema_properties": 0})
            stats["schema_properties_removed"] += 0  # already counted inside helper

    return spec, stats

# ------------------------------ CLI -------------------------------------- #

def is_json_file(path: Path) -> bool:
    return path.suffix.lower() == ".json" and not path.name.endswith(".media.json")

def process_path(in_path: Path, in_place: bool) -> Tuple[int, Dict[str, int]]:
    """
    Process a single file or a directory (non-recursive).
    Returns (files_processed, aggregate_stats).
    """
    files: List[Path] = []
    if in_path.is_file() and is_json_file(in_path):
        files = [in_path]
    elif in_path.is_dir():
        files = [p for p in sorted(in_path.glob("*.json")) if is_json_file(p)]
    else:
        return 0, {}

    total_stats = {
        "files": 0,
        "op_inline_params_removed": 0,
        "op_ref_params_removed": 0,
        "component_params_removed": 0,
        "schema_properties_removed": 0,
    }

    for f in files:
        spec = _json_load(f)
        cleaned, stats = clean_spec(spec)

        if in_place:
            out = f
        else:
            out = f.with_name(f"{f.stem}.clean.json")

        _json_save(out, cleaned)

        total_stats["files"] += 1
        for k in stats:
            total_stats[k] += stats[k]

    return total_stats["files"], total_stats

def main():
    ap = argparse.ArgumentParser(description="Remove auth params from OpenAPI specs")
    ap.add_argument("--in", dest="in_path", required=True, help="Input file or directory")
    ap.add_argument("--recursive", action="store_true", help="Recurse into subdirectories")
    ap.add_argument("--in-place", action="store_true", help="Overwrite input files instead of writing *.clean.json")
    args = ap.parse_args()

    in_path = Path(args.in_path)
    if not in_path.exists():
        raise SystemExit(f"Path not found: {in_path}")

    files_processed = 0
    aggregate = {
        "files": 0,
        "op_inline_params_removed": 0,
        "op_ref_params_removed": 0,
        "component_params_removed": 0,
        "schema_properties_removed": 0,
    }

    if in_path.is_file():
        n, stats = process_path(in_path, args.in_place)
        files_processed += n
        for k in aggregate:
            if k in stats:
                aggregate[k] += stats[k]
    elif in_path.is_dir() and not args.recursive:
        n, stats = process_path(in_path, args.in_place)
        files_processed += n
        for k in aggregate:
            if k in stats:
                aggregate[k] += stats[k]
    else:
        # recursive
        for sub in sorted(in_path.rglob("*.json")):
            if not is_json_file(sub):
                continue
            n, stats = process_path(sub, args.in_place)
            files_processed += n
            for k in aggregate:
                if k in stats:
                    aggregate[k] += stats[k]

    print(
        json.dumps(
            {
                "processed_files": files_processed,
                "stats": aggregate,
            },
            indent=2,
            sort_keys=True,
        )
    )

if __name__ == "__main__":
    main()
