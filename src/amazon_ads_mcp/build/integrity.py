"""Refresh-time integrity checks for the v1 catalog.

Locked checks from adsv1.md §4.9:

1. Charset: every field_id must match FIELD_ID_CHARSET.
2. Uniqueness: field_id is unique across dimensions + metrics combined.
3. Reference existence: every id in required_fields / complementary_fields
   exists in the combined catalog.
4. No cycles: the required_fields graph is acyclic.

These run at refresh time only. Runtime loader does not re-verify — it
relies on the refresh pipeline producing a clean catalog, backstopped by
catalog_meta.output_files_sha256 verification (see loader in Phase C).
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping, Set

from .validators import FIELD_ID_CHARSET


class CatalogIntegrityError(ValueError):
    """Raised when a catalog fails any refresh-time integrity check."""


def _iter_records(catalog: Mapping[str, Any]) -> Iterable[Dict[str, Any]]:
    for key in ("dimensions", "metrics"):
        for record in catalog.get(key, []) or []:
            yield record


def check_charset(catalog: Mapping[str, Any]) -> None:
    for record in _iter_records(catalog):
        fid = record.get("field_id")
        if not isinstance(fid, str) or not FIELD_ID_CHARSET.match(fid):
            raise CatalogIntegrityError(
                f"charset violation: field_id {fid!r} contains characters outside "
                f"[a-zA-Z0-9._-]"
            )


def check_uniqueness(catalog: Mapping[str, Any]) -> None:
    seen: Set[str] = set()
    for record in _iter_records(catalog):
        fid = record["field_id"]
        if fid in seen:
            raise CatalogIntegrityError(
                f"duplicate field_id {fid!r} found across dimensions + metrics"
            )
        seen.add(fid)


def _all_ids(catalog: Mapping[str, Any]) -> Set[str]:
    return {r["field_id"] for r in _iter_records(catalog)}


def check_references_exist(catalog: Mapping[str, Any]) -> None:
    ids = _all_ids(catalog)
    for record in _iter_records(catalog):
        fid = record["field_id"]
        for key in ("required_fields", "complementary_fields"):
            for ref in record.get(key, []) or []:
                if ref not in ids:
                    raise CatalogIntegrityError(
                        f"{fid!r}.{key} references unknown field {ref!r}"
                    )


def check_no_cycles(catalog: Mapping[str, Any]) -> None:
    """Cycle detection on the required_fields graph (DFS with path set)."""
    # Build adjacency from required_fields only — complementary_fields is advisory.
    graph: Dict[str, List[str]] = {}
    for record in _iter_records(catalog):
        graph[record["field_id"]] = list(record.get("required_fields", []) or [])

    WHITE, GRAY, BLACK = 0, 1, 2
    color: Dict[str, int] = {node: WHITE for node in graph}

    def dfs(node: str, path: List[str]) -> None:
        color[node] = GRAY
        path.append(node)
        for neighbor in graph.get(node, []):
            if color.get(neighbor) == GRAY:
                cycle_start = path.index(neighbor) if neighbor in path else 0
                cycle = " -> ".join(path[cycle_start:] + [neighbor])
                raise CatalogIntegrityError(
                    f"required_fields cycle detected: {cycle}"
                )
            if color.get(neighbor, BLACK) == WHITE:
                dfs(neighbor, path)
        path.pop()
        color[node] = BLACK

    for node in graph:
        if color[node] == WHITE:
            dfs(node, [])


#: Bug-fix-plan §1.5 — fraction of metric records that must carry non-empty
#: compatible_dimensions after refresh. Guards against the Issue 10 regression
#: class (refresh silently dropping compat lists).
COMPAT_FLOOR_FRACTION = 0.95


def check_compatibility_floor(catalog: Mapping[str, Any]) -> None:
    """Fail if fewer than COMPAT_FLOOR_FRACTION of metrics carry compat data.

    Only runs in production-flag refreshes. Fixture-size catalogs (used by
    unit tests) aren't large enough for a percentage floor to be meaningful.
    """
    metrics = catalog.get("metrics", []) or []
    # Threshold only meaningful for realistic catalogs (unit-test fixtures
    # are too small; production floors in refresh_v1_catalog.py gate this).
    if len(metrics) < 50:
        return
    populated = sum(1 for m in metrics if (m.get("compatible_dimensions") or []))
    fraction = populated / len(metrics)
    if fraction < COMPAT_FLOOR_FRACTION:
        raise CatalogIntegrityError(
            f"compatibility data populated for {fraction:.1%} of metrics "
            f"(floor: {COMPAT_FLOOR_FRACTION:.0%}); refresh likely dropped data. "
            f"Check _normalize_record category gate and source files."
        )


def check_catalog(catalog: Mapping[str, Any]) -> None:
    """Run every integrity check in a stable order.

    Order matters: charset first (fast-fail on artifact data), then
    uniqueness (required for the reference/cycle checks to be meaningful),
    then references, then cycles, then the compat floor (last because it
    assumes uniqueness is already established).
    """
    check_charset(catalog)
    check_uniqueness(catalog)
    check_references_exist(catalog)
    check_no_cycles(catalog)
    check_compatibility_floor(catalog)
