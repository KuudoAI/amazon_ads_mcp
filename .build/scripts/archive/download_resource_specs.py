#!/usr/bin/env python3
"""
Best-of-both OpenAPI processor for Amazon Ads:

- Split (default): download and/or load specs, filter paths by resource patterns,
  tree-shake components, preserve globals, export media inventory, validate.
- Merge (optional): produce a single merged spec with namespaced components for analysis.

Outputs are deterministic and only rewritten on change.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import httpx
import yaml

try:
    from openapi_spec_validator import validate_spec
    VALIDATE = True
except Exception:
    VALIDATE = False


# ------------------------------- Utilities ------------------------------- #

def sha1(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8")).hexdigest()  # nosec


def stable_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, indent=2, ensure_ascii=False)


def deep_get(d: dict, *path, default=None):
    cur = d
    for p in path:
        if not isinstance(cur, dict) or p not in cur:
            return default
        cur = cur[p]
    return cur


def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def jsonify_keys(x: Any) -> Any:
    """
    Recursively convert dict keys to strings so YAML-derived specs with
    non-string keys (e.g., 200 under responses) serialize deterministically.
    """
    if isinstance(x, dict):
        return {str(k): jsonify_keys(v) for k, v in x.items()}
    if isinstance(x, list):
        return [jsonify_keys(i) for i in x]
    return x


def strip_empty_external_docs(x: Any) -> Any:
    """
    Recursively remove 'externalDocs' objects that lack a required 'url'.
    This quiets validator warnings from upstream specs that include {}.
    """
    if isinstance(x, dict):
        out = {}
        for k, v in x.items():
            if k == "externalDocs" and isinstance(v, dict) and not v.get("url"):
                continue
            out[k] = strip_empty_external_docs(v)
        return out
    if isinstance(x, list):
        return [strip_empty_external_docs(i) for i in x]
    return x


# ----------------------------- Media Inventory --------------------------- #

def build_media_inventory_for_paths(paths: Dict[str, Any]) -> Dict[str, Any]:
    media = {"requests": {}, "responses": {}}
    for raw_path, ops in (paths or {}).items():
        if not isinstance(ops, dict):
            continue
        for method, op in ops.items():
            if not isinstance(op, dict):
                continue
            m = method.lower()
            key = f"{m} {raw_path}"

            # requestBody: pick stable "first" media if multiple
            rb = op.get("requestBody") or {}
            rb_content = rb.get("content") or {}
            if isinstance(rb_content, dict) and rb_content:
                first_media = sorted(map(str, rb_content.keys()))[0]
                media["requests"][key] = first_media

            # responses: union of declared content types
            accepts: Set[str] = set()
            responses = op.get("responses") or {}
            if isinstance(responses, dict):
                for resp in responses.values():
                    rc = (resp or {}).get("content") or {}
                    if isinstance(rc, dict):
                        accepts.update(map(str, rc.keys()))
            if accepts:
                media["responses"][key] = sorted(accepts)
    return media


# --------------------------- Reference collection ------------------------ #

def collect_refs(obj: Any, refs: Set[str] | None = None) -> Set[str]:
    if refs is None:
        refs = set()
    if isinstance(obj, dict):
        ref = obj.get("$ref")
        if isinstance(ref, str) and ref.startswith("#/components/"):
            refs.add(ref)
        for v in obj.values():
            collect_refs(v, refs)
    elif isinstance(obj, list):
        for item in obj:
            collect_refs(item, refs)
    return refs


def extract_component(spec: Dict[str, Any], ref: str) -> Any:
    if not ref.startswith("#/components/"):
        return None
    path = ref.split("#/", 1)[-1]
    cur: Any = spec
    for part in path.split("/"):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


# ---------------------------- Split / Isolate ---------------------------- #

COMPONENT_SECTIONS = [
    "schemas", "parameters", "responses", "requestBodies",
    "headers", "examples", "links", "callbacks", "securitySchemes"
]

@dataclass
class SplitResult:
    namespace: str
    spec: Dict[str, Any]
    media: Dict[str, Any]
    stats: Dict[str, Any]


class Splitter:
    def __init__(self, out_dir: Path):
        self.out_dir = out_dir
        ensure_dir(self.out_dir)

    @staticmethod
    def path_matches_any(path: str, patterns: List[str]) -> bool:
        """Substring or prefix match (simple & robust)."""
        if not patterns:
            return True
        for pat in patterns:
            if not pat:
                continue
            if pat in path:
                return True
            if pat.startswith("/") and path.startswith(pat):
                return True
        return False

    def filter_paths(self, full_spec: Dict[str, Any], patterns: List[str]) -> Dict[str, Any]:
        all_paths = full_spec.get("paths", {}) or {}
        if not all_paths:
            return {}
        if not patterns:
            return all_paths
        kept = {p: ops for p, ops in all_paths.items() if self.path_matches_any(p, patterns)}
        return kept or all_paths  # fail open

    def _seed_globals(self, full_spec: Dict[str, Any], isolated: Dict[str, Any]) -> None:
        """Copy top-level globals we want to preserve."""
        for key in ("servers", "tags", "externalDocs", "security"):
            if key in full_spec:
                isolated[key] = json.loads(stable_json(full_spec[key]))

        # Always ensure components skeleton exists
        comps = isolated.setdefault("components", {})
        for sec in COMPONENT_SECTIONS:
            comps.setdefault(sec, {})

        # carry through securitySchemes wholesale (auth wiring)
        src_sec = deep_get(full_spec, "components", "securitySchemes", default={})
        isolated["components"]["securitySchemes"] = json.loads(stable_json(src_sec))

    def _tree_shake_components(self, full_spec: Dict[str, Any], isolated: Dict[str, Any]) -> None:
        """Copy only the referenced components (recursive)."""
        used: Set[str] = set()

        # Collect $refs from paths first
        collect_refs(isolated.get("paths", {}), used)

        # Iteratively pull in referenced components and their nested refs
        changed = True
        while changed:
            changed = False
            new_refs: Set[str] = set()
            for ref in list(used):
                obj = extract_component(full_spec, ref)
                if obj is None:
                    continue
                # Place into isolated components
                parts = ref.split("#/components/")[-1].split("/")
                if len(parts) < 2:
                    continue
                section, name = parts[0], parts[1]
                if section not in COMPONENT_SECTIONS:
                    continue
                dest = isolated["components"].setdefault(section, {})
                if name not in dest:
                    dest[name] = json.loads(stable_json(obj))
                    # gather nested refs inside this component
                    collect_refs(obj, new_refs)
                    changed = True
            used |= new_refs

        # Optional: clean empty component sections (but keep dicts present)
        for sec in COMPONENT_SECTIONS:
            isolated["components"].setdefault(sec, {})

    @staticmethod
    def _normalize_amazon_header_components(spec: Dict[str, Any]) -> None:
        """
        Fix common upstream header names and ensure schema + required flags.
        - Amazon-Ads-ClientId -> Amazon-Advertising-API-ClientId
        - Ensure Scope header has schema and is required
        - Ensure both canonical components exist
        """
        comps = spec.setdefault("components", {})
        params = comps.setdefault("parameters", {})

        # Fix existing misnamed or incomplete headers
        for _, p in list(params.items()):
            if not isinstance(p, dict) or p.get("in") != "header":
                continue
            if p.get("name") == "Amazon-Ads-ClientId":
                p["name"] = "Amazon-Advertising-API-ClientId"
                p["required"] = True
                p.setdefault("schema", {"type": "string"})
            if p.get("name") == "Amazon-Advertising-API-Scope":
                p.setdefault("schema", {"type": "string"})
                p["required"] = True

        params.setdefault("ClientIdHeader", {
            "description": "LWA client id header.",
            "in": "header",
            "name": "Amazon-Advertising-API-ClientId",
            "required": True,
            "schema": {"type": "string"},
        })
        params.setdefault("ScopeHeader", {
            "description": "Amazon Ads profile scope header.",
            "in": "header",
            "name": "Amazon-Advertising-API-Scope",
            "required": True,
            "schema": {"type": "string"},
        })

    @staticmethod
    def _inject_headers_and_media_defaults(spec: Dict[str, Any]) -> None:
        """
        Attach header parameters to every operation (idempotent).
        If an op has a single request/response media type, set defaults
        for Content-Type and Accept (as header parameters).
        """
        def ensure_op_header(op: Dict[str, Any], name: str, default: str | None = None):
            params = op.setdefault("parameters", [])
            for p in params:
                if p.get("in") == "header" and p.get("name") == name:
                    return
            param_obj = {"name": name, "in": "header", "required": True, "schema": {"type": "string"}}
            if default:
                param_obj["schema"]["default"] = default
            params.append(param_obj)

        paths = spec.get("paths") or {}
        for _, item in paths.items():
            if not isinstance(item, dict):
                continue
            for method in ("get","put","post","delete","options","head","patch","trace"):
                op = item.get(method)
                if not isinstance(op, dict):
                    continue

                # Required Amazon headers on every op
                ensure_op_header(op, "Amazon-Advertising-API-ClientId")
                ensure_op_header(op, "Amazon-Advertising-API-Scope")

                # Request Content-Type default if there is exactly one choice
                rb = op.get("requestBody") or {}
                content = rb.get("content") or {}
                if isinstance(content, dict) and len(content) == 1:
                    ct = next(iter(content.keys()))
                    ensure_op_header(op, "Content-Type", default=str(ct))

                # Accept default from union of response content types (pick first sorted)
                resp = op.get("responses") or {}
                accept_types: list[str] = []
                if isinstance(resp, dict):
                    for r in resp.values():
                        rc = (r or {}).get("content") or {}
                        if isinstance(rc, dict):
                            accept_types += list(map(str, rc.keys()))
                if accept_types:
                    accept = sorted(set(accept_types))[0]
                    ensure_op_header(op, "Accept", default=accept)

    def build_isolated_spec(self, full_spec: Dict[str, Any], namespace: str, patterns: List[str]) -> SplitResult:
        paths = self.filter_paths(full_spec, patterns)

        isolated: Dict[str, Any] = {
            "openapi": full_spec.get("openapi", "3.0.1"),
            "info": {
                "title": f"Amazon Ads API - {namespace}",
                "version": deep_get(full_spec, "info", "version", default="1.0.0"),
                "description": f"Isolated spec for {', '.join(patterns) or 'ALL'}",
            },
            "paths": paths,
            "components": {k: {} for k in COMPONENT_SECTIONS},
        }

        # Seed globals and securitySchemes
        self._seed_globals(full_spec, isolated)

        # Tree-shake components used by kept paths
        self._tree_shake_components(full_spec, isolated)

        # Normalize & ensure presence of header components
        self._normalize_amazon_header_components(isolated)

        # Inject header usage + media defaults per operation
        self._inject_headers_and_media_defaults(isolated)

        # Media inventory AFTER header/media injections (doesn't matter, but consistent)
        media = build_media_inventory_for_paths(isolated.get("paths", {}))

        # Strip empty externalDocs
        cleaned = strip_empty_external_docs(isolated)

        # Optional validation
        if VALIDATE:
            try:
                validate_spec(jsonify_keys(cleaned))
            except Exception as e:
                print(f"  ⚠️  OpenAPI validation warning for {namespace}: {e}")

        stats = {
            "paths": len(paths),
            "schemas": len(cleaned["components"]["schemas"]),
            "size_bytes": None,
        }
        return SplitResult(namespace=namespace, spec=cleaned, media=media, stats=stats)


# ------------------------------- Downloader ------------------------------ #

class Downloader:
    def __init__(self, cache_dir: Path):
        self.cache_dir = cache_dir
        ensure_dir(self.cache_dir)
        self._client = httpx.Client(timeout=30.0, follow_redirects=True)

    def _cache_path(self, url: str) -> Path:
        return self.cache_dir / f"{sha1(url)}.json"

    def get(self, url: str) -> Dict[str, Any]:
        cache_file = self._cache_path(url)
        etag_file = cache_file.with_suffix(".etag")
        headers = {}
        if etag_file.exists():
            headers["If-None-Match"] = etag_file.read_text().strip()

        print(f"  Downloading {url}")
        resp = self._client.get(url, headers=headers)
        if resp.status_code == 304 and cache_file.exists():
            print("  Using cached version (ETag match)")
            return json.loads(cache_file.read_text(encoding="utf-8"))

        resp.raise_for_status()
        if url.endswith((".yaml", ".yml")):
            spec = yaml.safe_load(resp.text)
        else:
            spec = resp.json()

        # Make keys JSON-safe before stable dump (YAML may have int keys like 200)
        spec_for_cache = jsonify_keys(spec)
        cache_file.write_text(stable_json(spec_for_cache), encoding="utf-8")

        etag = resp.headers.get("ETag")
        if etag:
            etag_file.write_text(etag, encoding="utf-8")
        return spec


# ------------------------------- Merger (opt) ---------------------------- #

def update_refs_with_namespace(obj: Any, namespace: str):
    if isinstance(obj, dict):
        if "$ref" in obj and isinstance(obj["$ref"], str):
            ref = obj["$ref"]
            if ref.startswith("#/components/schemas/"):
                name = ref.split("/")[-1]
                if not name.startswith(f"{namespace}_"):
                    obj["$ref"] = f"#/components/schemas/{namespace}_{name}"
            elif ref.startswith("#/components/parameters/"):
                name = ref.split("/")[-1]
                if not name.startswith(f"{namespace}_"):
                    obj["$ref"] = f"#/components/parameters/{namespace}_{name}"
            elif ref.startswith("#/components/responses/"):
                name = ref.split("/")[-1]
                if not name.startswith(f"{namespace}_"):
                    obj["$ref"] = f"#/components/responses/{namespace}_{name}"
            elif ref.startswith("#/components/requestBodies/"):
                name = ref.split("/")[-1]
                if not name.startswith(f"{namespace}_"):
                    obj["$ref"] = f"#/components/requestBodies/{namespace}_{name}"
        for v in obj.values():
            update_refs_with_namespace(v, namespace)
    elif isinstance(obj, list):
        for item in obj:
            update_refs_with_namespace(item, namespace)


def merge_specs_with_namespace(specs: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    merged = {
        "openapi": "3.0.1",
        "info": {"title": "Amazon Ads API - Merged (debug)", "version": "1.0.0"},
        "paths": {},
        "components": {
            "schemas": {}, "parameters": {}, "responses": {}, "requestBodies": {},
            "headers": {}, "examples": {}, "links": {}, "callbacks": {}, "securitySchemes": {}
        },
    }
    for namespace, spec in specs.items():
        # Paths (warn on collisions)
        for path, defn in (spec.get("paths") or {}).items():
            if path in merged["paths"]:
                print(f"  ⚠️ Path collision: {path}")
            path_copy = json.loads(stable_json(defn))
            update_refs_with_namespace(path_copy, namespace)
            merged["paths"][path] = path_copy

        comps = spec.get("components") or {}
        for section in COMPONENT_SECTIONS:
            dest = merged["components"].setdefault(section, {})
            src = comps.get(section) or {}
            for name, defn in src.items():
                namespaced = f"{namespace}_{name}"
                copy_defn = json.loads(stable_json(defn))
                update_refs_with_namespace(copy_defn, namespace)
                dest[namespaced] = copy_defn
    return merged


# --------------------------------- Driver -------------------------------- #

def write_if_changed(path: Path, content: str) -> None:
    old = path.read_text(encoding="utf-8") if path.exists() else None
    if content != old:
        path.write_text(content, encoding="utf-8")


def run_split_mode(
    out_dir: Path,
    config_path: Optional[Path],
    source_dir: Optional[Path],
    validation_report_path: Optional[Path] = None,
):
    ensure_dir(out_dir)
    # Mirror into server resources dir
    resources_dir = out_dir / "resources"
    ensure_dir(resources_dir)

    report: List[Dict[str, Any]] = []

    # Load from config (download) or from source_dir (local)
    jobs: List[Tuple[str, Dict[str, Any], List[str]]] = []
    downloader = Downloader(out_dir / ".cache") if config_path else None

    if config_path:
        cfg = json.loads(config_path.read_text(encoding="utf-8"))
        downloads = cfg.get("openapiDownloads", [])
        active = [
            d for d in downloads
            if str(d.get("active", True)).strip().lower() in {"true", "1", "yes", "y"}
        ]
        print(f"Processing {len(active)} active resources (config mode)")
        for dl in active:
            namespace = dl["namespace"]
            url = dl["downloadLink"]
            patterns: List[str] = dl.get("resources") or dl.get("pathPatterns") or []
            try:
                full = downloader.get(url)  # type: ignore
                jobs.append((namespace, full, patterns))
            except Exception as e:
                print(f"  ❌ Download failed for {namespace}: {e}")
                report.append({"type": "error", "namespace": namespace, "message": str(e)})
    elif source_dir:
        files = sorted(source_dir.rglob("*.json"))
        print(f"Processing {len(files)} specs (local folder mode)")
        for f in files:
            namespace = "_".join(f.relative_to(source_dir).with_suffix("").parts)
            try:
                full = json.loads(f.read_text(encoding="utf-8"))
                jobs.append((namespace, full, []))  # patterns optional here
            except Exception as e:
                print(f"  ❌ Load failed for {f}: {e}")
                report.append({"type": "error", "file": str(f), "message": str(e)})
    else:
        raise SystemExit("Either --config or --source is required for split mode.")

    splitter = Splitter(out_dir)
    for namespace, full_spec, patterns in jobs:
        print(f"\n==> {namespace} (patterns: {', '.join(patterns) or 'ALL'})")
        try:
            res = splitter.build_isolated_spec(full_spec, namespace, patterns)

            # Primary flat outputs (backward-compatible)
            spec_path = out_dir / f"{namespace}.json"
            media_path = out_dir / f"{namespace}.media.json"

            spec_json = stable_json(jsonify_keys(res.spec))
            write_if_changed(spec_path, spec_json)
            write_if_changed(media_path, stable_json(res.media))

            # Mirror spec into resources/ for the mounted MCP server
            spec_path_resources = resources_dir / f"{namespace}.json"
            write_if_changed(spec_path_resources, spec_json)

            size = spec_path.stat().st_size if spec_path.exists() else 0
            res.stats["size_bytes"] = size

            print(f"  ✅ {spec_path.name}  paths={res.stats['paths']}  schemas={res.stats['schemas']}  size={size/1024:.1f}KB")
            print(f"  📄 media -> {media_path.name}")
            print(f"  📦 server resources -> resources/{spec_path_resources.name}")

        except Exception as e:
            print(f"  ❌ Error building {namespace}: {e}")
            report.append({"type": "error", "namespace": namespace, "message": str(e)})

    if validation_report_path:
        write_if_changed(validation_report_path, stable_json(report))
        print(f"\nValidation report: {validation_report_path}")

def run_merge_mode(source_dir: Path, out_file: Path):
    """Optional: Merge existing isolated specs to a single file with namespaced components (debugging only)."""
    files = sorted(source_dir.glob("*.json"))
    print(f"Merging {len(files)} isolated specs from {source_dir}")
    specs: Dict[str, Dict[str, Any]] = {}
    for f in files:
        if f.name.endswith(".media.json") or f.name == out_file.name:
            continue
        namespace = f.stem
        try:
            specs[namespace] = json.loads(f.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"  ❌ Load failed for {f}: {e}")

    merged = merge_specs_with_namespace(specs)
    if VALIDATE:
        try:
            to_validate = strip_empty_external_docs(jsonify_keys(merged))
            validate_spec(to_validate)
        except Exception as e:
            print(f"  ⚠️  Merged spec validation warning: {e}")
    write_if_changed(out_file, stable_json(jsonify_keys(merged)))
    print(f"  ✅ Wrote merged spec: {out_file}  size={out_file.stat().st_size/1024/1024:.2f}MB")


def main():
    ap = argparse.ArgumentParser(description="Best-of-both OpenAPI splitter/merger for Amazon Ads MCP")
    ap.add_argument("--mode", choices=["split", "merge"], default="split")
    ap.add_argument("--config", type=Path, help="config/amazon_ads_openapi2.json (for download & split)")
    ap.add_argument("--source", type=Path, help="Directory of existing specs (use in split or merge modes)")
    ap.add_argument("--out", type=Path, required=True, help="Output directory")
    ap.add_argument("--merged-file", type=Path, help="Output file for merge mode (default: OUT/merged_with_namespaces.json)")
    ap.add_argument("--report", type=Path, help="Validation report path (split mode)")
    args = ap.parse_args()

    if args.mode == "split":
        run_split_mode(
            out_dir=args.out,
            config_path=args.config,
            source_dir=args.source,
            validation_report_path=args.report or (args.out / "validation_report.json"),
        )
    else:
        merged_file = args.merged_file or (args.out / "merged_with_namespaces.json")
        src = args.source or args.out
        run_merge_mode(src, merged_file)


if __name__ == "__main__":
    main()
