"""Commit-signal-verified loader for the packaged v1 report-fields catalog.

The packaged artifacts live under ``src/amazon_ads_mcp/resources/adsv1/``:

- ``dimensions.json`` — array of dimension records
- ``metrics.json`` — array of metric records
- ``index.json`` — routing map ``{field_id: {file, category}}``
- ``catalog_meta.json`` — provenance manifest and commit signal

The loader is **lock-free** and **lazy**: no I/O at import, first public
call parses the required files exactly once per process under normal
conditions. Under concurrent first-calls two threads may both parse the
same file; both produce identical results, so one is discarded. Do **not**
add a lock without measured evidence that duplicate parses cause harm.

Commit-signal contract (see adsv1.md §4.1):

1. ``catalog_meta.json`` must exist; missing → ``CATALOG_SCHEMA_MISMATCH``.
2. ``schema_version`` must equal ``SUPPORTED_SCHEMA_VERSION`` in either
   direction — old runtime + new catalog and new runtime + old catalog
   both fail closed.
3. On-disk SHA-256 of ``dimensions.json`` and ``metrics.json`` must match
   ``catalog_meta.output_files_sha256``. Any mismatch indicates an
   interrupted refresh and fails closed with ``CATALOG_SCHEMA_MISMATCH``.

The loader opens **only** the four named files. Stray ``*.json`` and
``*.tmp`` files under the catalog directory are never enumerated.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from .report_fields_errors import ReportFieldsErrorCode

#: The runtime-supported schema version. Bumping this requires a reader
#: update in the same commit (see adsv1.md §4.7).
SUPPORTED_SCHEMA_VERSION = 1

#: Explicit file list — no globs, no enumeration. Adding a new packaged
#: file requires updating this dict AND the refresh CLI commit order.
_CATALOG_FILES: Dict[str, str] = {
    "metrics": "metrics.json",
    "dimensions": "dimensions.json",
}
_META_FILE = "catalog_meta.json"
_INDEX_FILE = "index.json"


class CatalogSchemaError(RuntimeError):
    """Raised when the packaged catalog fails the commit-signal contract."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.code = ReportFieldsErrorCode.CATALOG_SCHEMA_MISMATCH


# ---------- lock-free lazy state (see module docstring) ------------------

_CATALOG_DIR: Optional[Path] = None
_META: Optional[Dict[str, Any]] = None
_INDEX: Optional[Dict[str, Any]] = None
_DIMENSIONS: Optional[List[Dict[str, Any]]] = None
_METRICS: Optional[List[Dict[str, Any]]] = None


def _default_catalog_dir() -> Path:
    """Default packaged catalog directory (as shipped in the wheel)."""
    return Path(__file__).resolve().parent.parent / "resources" / "adsv1"


def _catalog_dir() -> Path:
    return _CATALOG_DIR if _CATALOG_DIR is not None else _default_catalog_dir()


def set_catalog_dir(path: Optional[Path]) -> None:
    """Override the catalog directory (tests only) and reset lazy caches.

    Passing ``None`` restores the default packaged location. Never call
    this from runtime code.
    """
    global _CATALOG_DIR, _META, _INDEX, _DIMENSIONS, _METRICS
    _CATALOG_DIR = Path(path) if path is not None else None
    _META = None
    _INDEX = None
    _DIMENSIONS = None
    _METRICS = None


# ---------- IO + verification helpers ------------------------------------


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_json(path: Path) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _load_meta() -> Dict[str, Any]:
    """Load and verify ``catalog_meta.json``. Idempotent; cached."""
    global _META
    if _META is not None:
        return _META

    directory = _catalog_dir()
    meta_path = directory / _META_FILE
    if not meta_path.exists():
        raise CatalogSchemaError(
            f"catalog_meta.json not found at {meta_path} — refresh never completed"
        )

    meta = _read_json(meta_path)
    version = meta.get("schema_version")
    if version != SUPPORTED_SCHEMA_VERSION:
        raise CatalogSchemaError(
            f"catalog schema_version={version!r} does not match runtime "
            f"SUPPORTED_SCHEMA_VERSION={SUPPORTED_SCHEMA_VERSION} "
            f"(strict: fails closed in either direction)"
        )

    # Verify on-disk hashes of the data files match the commit manifest.
    expected = meta.get("output_files_sha256") or {}
    for fname in ("dimensions.json", "metrics.json"):
        data_path = directory / fname
        if not data_path.exists():
            raise CatalogSchemaError(
                f"interrupted refresh detected — {fname} missing under {directory}"
            )
        actual = _sha256_file(data_path)
        if expected.get(fname) != actual:
            raise CatalogSchemaError(
                f"interrupted refresh detected — on-disk {fname} sha256 does not "
                f"match catalog_meta.output_files_sha256"
            )

    _META = meta
    return _META


def _load_index_file() -> Dict[str, Any]:
    global _INDEX
    if _INDEX is not None:
        return _INDEX
    _load_meta()  # commit-signal verification runs first
    _INDEX = _read_json(_catalog_dir() / _INDEX_FILE)
    return _INDEX


def _load_records(kind: str) -> List[Dict[str, Any]]:
    """Load either 'dimensions' or 'metrics' as a list of records."""
    global _DIMENSIONS, _METRICS
    if kind == "dimensions":
        if _DIMENSIONS is None:
            _load_meta()
            _DIMENSIONS = _read_json(_catalog_dir() / _CATALOG_FILES["dimensions"])
        return _DIMENSIONS
    if kind == "metrics":
        if _METRICS is None:
            _load_meta()
            _METRICS = _read_json(_catalog_dir() / _CATALOG_FILES["metrics"])
        return _METRICS
    raise ValueError(f"unknown catalog kind {kind!r}")


# ---------- public API ---------------------------------------------------


def get_catalog_meta() -> Dict[str, Any]:
    """Return a shallow copy of catalog_meta.json payload."""
    return dict(_load_meta())


def get_index() -> Dict[str, Any]:
    """Return the routing map ``{field_id: {file, category}}``."""
    return _load_index_file()


def get_dimensions() -> List[Dict[str, Any]]:
    return _load_records("dimensions")


def get_metrics() -> List[Dict[str, Any]]:
    return _load_records("metrics")


def lookup_field(field_id: str) -> Optional[Dict[str, Any]]:
    """O(routing+linear) single-field detail lookup.

    Consults ``index.json`` first to decide which file to scan, then
    walks that file linearly. For a 700-entry list the scan is negligible.
    """
    index = _load_index_file()
    entry = (index.get("fields") or {}).get(field_id)
    if entry is None:
        return None
    records = _load_records(entry["file"])
    for record in records:
        if record.get("field_id") == field_id:
            return record
    return None


def load_catalog() -> Dict[str, Any]:
    """Force-load every catalog file. Useful for CI smoke tests."""
    _load_meta()
    _load_index_file()
    _load_records("dimensions")
    _load_records("metrics")
    return {"meta": _META, "index": _INDEX}
