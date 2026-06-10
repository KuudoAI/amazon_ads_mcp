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
_LABEL_INDEX_FILE = "dimension_label_index.json"


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
_DIM_LABEL_INDEX: Optional[Dict[str, List[str]]] = None


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
    global _CATALOG_DIR, _META, _INDEX, _DIMENSIONS, _METRICS, _DIM_LABEL_INDEX
    _CATALOG_DIR = Path(path) if path is not None else None
    _META = None
    _INDEX = None
    _DIMENSIONS = None
    _METRICS = None
    _DIM_LABEL_INDEX = None


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
    # dimension_label_index.json is verified when present in the manifest
    # so old catalog_meta.json lacking that entry still loads cleanly
    # (schema_version bumps would fail closed via the version check above).
    expected = meta.get("output_files_sha256") or {}
    required_names = ["dimensions.json", "metrics.json"]
    if "dimension_label_index.json" in expected:
        required_names.append("dimension_label_index.json")
    for fname in required_names:
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


def get_dimension_label_index() -> Dict[str, List[str]]:
    """Return the ``{display_label: [field_id, ...]}`` map for dimensions.

    Amazon's source data stores display labels (e.g. ``"Ad group"``) inside
    metric compatibility lists rather than canonical field IDs. This map
    enables the handler to resolve either form in ``compatible_with`` and
    validate-mode incompatible-pair checks. See bug_fix_plan.md §2.

    Returns an empty dict if the catalog predates the label-index file
    (old catalog + new runtime — see §4.7 strict versioning).
    """
    global _DIM_LABEL_INDEX
    if _DIM_LABEL_INDEX is not None:
        return _DIM_LABEL_INDEX
    _load_meta()  # commit-signal verification runs first
    path = _catalog_dir() / _LABEL_INDEX_FILE
    if not path.exists():
        _DIM_LABEL_INDEX = {}
        return _DIM_LABEL_INDEX
    payload = _read_json(path)
    labels = payload.get("labels", {}) if isinstance(payload, dict) else {}
    _DIM_LABEL_INDEX = {k: list(v) for k, v in labels.items()}
    return _DIM_LABEL_INDEX


def get_dimensions() -> List[Dict[str, Any]]:
    return _load_records("dimensions")


def get_metrics() -> List[Dict[str, Any]]:
    return _load_records("metrics")


# ---------- curated time-grain windows (category="time") -----------------
#
# Doc-sourced overlay for the v1 reporting API's time grains. The packaged
# OpenAPI spec does NOT enumerate per-grain date-range presets or the
# historical-data / max-report-pull windows, so an LLM otherwise guesses a
# time selection and eats an HTTP 400 — the same field-discovery failure the
# rest of report_fields closes, extended to the time axis.
#
# This is a CURATED CONSTANT, not generated catalog content. It deliberately
# lives in code (not in dimensions.json) so the refresh pipeline's
# catalog-drift / idempotency guards stay green and the loader's "four named
# files" contract is untouched. The descriptive text (display_name,
# short_description, data_type) mirrors the corresponding catalog dimension
# records so the two views agree.
#
# Mapping note: the Amazon doc lists a "Day of week" grain with no
# corresponding catalog field_id (the catalog's ``day.value`` is "Day of
# Month"), so it is intentionally omitted rather than mapped to a phantom id.
#
# Source: Amazon Ads "Reporting — time periods" guide (date-range presets,
# historical data, and max report pull per time dimension).
_TIME_PRESETS_HOUR = ["Today", "Yesterday", "Last 7 days", "This week", "Last week"]
_TIME_PRESETS_DATE = _TIME_PRESETS_HOUR + [
    "Last 30 days",
    "This month",
    "Last month",
    "Last 90 days",
    "This quarter",
]
_TIME_PRESETS_YEARLY = _TIME_PRESETS_DATE + ["This year"]
_TIME_PRESETS_FULL = _TIME_PRESETS_YEARLY + ["Last year"]

#: Time-grain records in catalog-record shape, carrying the curated window
#: overlay. ``category="time"`` so they read as a distinct discovery facet;
#: the same field_ids also exist as ``category="dimension"`` catalog records
#: (their compatibility-graph home). Returned via :func:`get_time_records`.
TIME_GRAIN_RECORDS: List[Dict[str, Any]] = [
    {
        "field_id": "hour.value",
        "display_name": "Hour (Primary Key)",
        "data_type": "LONG",
        "category": "time",
        "provenance": "documented",
        "short_description": "The hour of the day associated with the report.",
        "required_fields": [],
        "complementary_fields": [],
        "date_range_presets": list(_TIME_PRESETS_HOUR),
        "historical_data": "14 days",
        "max_report_pull": "14 days",
    },
    {
        "field_id": "date.value",
        "display_name": "Date (Primary Key)",
        "data_type": "DATE",
        "category": "time",
        "provenance": "documented",
        "short_description": "The date included in the report.",
        "required_fields": [],
        "complementary_fields": [],
        "date_range_presets": list(_TIME_PRESETS_DATE),
        "historical_data": "15 months",
        "max_report_pull": "120 days",
    },
    {
        "field_id": "day.value",
        "display_name": "Day of Month (Primary Key)",
        "data_type": "LONG",
        "category": "time",
        "provenance": "documented",
        "short_description": "The day of the month associated with the report.",
        "required_fields": [],
        "complementary_fields": [],
        "date_range_presets": list(_TIME_PRESETS_YEARLY),
        "historical_data": "15 months",
        "max_report_pull": "15 months",
    },
    {
        "field_id": "week.value",
        "display_name": "Week (Primary Key)",
        "data_type": "LONG",
        "category": "time",
        "provenance": "documented",
        "short_description": "The week of the year associated with the report.",
        "required_fields": [],
        "complementary_fields": [],
        "date_range_presets": list(_TIME_PRESETS_YEARLY),
        "historical_data": "15 months",
        "max_report_pull": "15 months",
    },
    {
        "field_id": "month.value",
        "display_name": "Month (Primary Key)",
        "data_type": "LONG",
        "category": "time",
        "provenance": "documented",
        "short_description": "The month of the year associated with the report.",
        "required_fields": [],
        "complementary_fields": [],
        "date_range_presets": list(_TIME_PRESETS_FULL),
        "historical_data": "72 months",
        "max_report_pull": "25 months",
    },
    {
        "field_id": "year.value",
        "display_name": "Year (Primary Key)",
        "data_type": "LONG",
        "category": "time",
        "provenance": "documented",
        "short_description": "The year associated with the report.",
        "required_fields": [],
        "complementary_fields": [],
        "date_range_presets": list(_TIME_PRESETS_FULL),
        "historical_data": "72 months",
        "max_report_pull": "72 months",
    },
    {
        "field_id": "dateRange.value",
        "display_name": "Date range (Primary Key)",
        "data_type": "DATE_RANGE",
        "category": "time",
        "provenance": "documented",
        "short_description": "The date range associated with the report.",
        "required_fields": [],
        "complementary_fields": [],
        "date_range_presets": list(_TIME_PRESETS_FULL),
        "historical_data": "72 months",
        "max_report_pull": "72 months",
    },
]


def get_time_records() -> List[Dict[str, Any]]:
    """Return deep copies of the curated time-grain records.

    Independent of the loaded catalog files — the window overlay is a
    code-level constant, so this works even when the on-disk catalog has no
    time dimensions. Copies are returned so callers can mutate freely
    without corrupting the shared constant.
    """
    return [
        {**rec, "date_range_presets": list(rec["date_range_presets"])}
        for rec in TIME_GRAIN_RECORDS
    ]


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
    get_dimension_label_index()
    return {"meta": _META, "index": _INDEX, "labels": _DIM_LABEL_INDEX}
