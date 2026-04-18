"""Tests for the commit-signal-verified v1 catalog loader.

Locked contract from adsv1.md §4.1 + §4.7:
- Lock-free lazy load; no I/O at import.
- Opens only four named files (never *.tmp, never strays).
- catalog_meta.json is the commit signal: missing, wrong version (either
  direction), or hash-mismatched → CATALOG_SCHEMA_MISMATCH.
"""

from __future__ import annotations

import builtins
import hashlib
import importlib
import json
import sys
from pathlib import Path

import pytest


# ---------- lazy-load fixtures ----------------------------------------------


@pytest.fixture
def fresh_loader():
    """Return the loader module with caches reset and catalog_dir un-set.

    Importing this fixture guarantees a fresh module state in every test so
    module-level sentinels don't leak between tests.
    """
    # Drop any prior import so module-level sentinels are re-initialized fresh.
    sys.modules.pop("amazon_ads_mcp.tools.report_fields_v1_catalog", None)
    module = importlib.import_module("amazon_ads_mcp.tools.report_fields_v1_catalog")
    yield module
    # Clean up the test-only override on teardown.
    module.set_catalog_dir(None)


@pytest.fixture
def happy_catalog_dir(tmp_path: Path):
    """Build a minimal valid packaged catalog (2 records) under tmp_path."""
    dims = [
        {
            "field_id": "campaign.id",
            "display_name": "Campaign id",
            "data_type": "STRING",
            "category": "dimension",
            "provenance": "documented",
            "short_description": "Campaign id.",
            "description": "Campaign id.",
            "required_fields": [],
            "complementary_fields": [],
            "compatible_dimensions": [],
            "incompatible_dimensions": [],
            "v3_name_dsp": None,
            "v3_name_sponsored_ads": None,
            "source": {"md_file": "x.md", "parsed_at": "2026-01-01T00:00:00Z"},
        }
    ]
    metrics = [
        {
            "field_id": "metric.clicks",
            "display_name": "Clicks",
            "data_type": "INTEGER",
            "category": "metric",
            "provenance": "documented",
            "short_description": "Clicks.",
            "description": "Clicks.",
            "required_fields": [],
            "complementary_fields": [],
            "v3_name_dsp": None,
            "v3_name_sponsored_ads": None,
            "source": {"md_file": "y.md", "parsed_at": "2026-01-01T00:00:00Z"},
        }
    ]

    def _sorted_bytes(obj):
        return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8") + b"\n"

    dims_bytes = _sorted_bytes(dims)
    metrics_bytes = _sorted_bytes(metrics)
    (tmp_path / "dimensions.json").write_bytes(dims_bytes)
    (tmp_path / "metrics.json").write_bytes(metrics_bytes)
    (tmp_path / "index.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "fields": {
                    "campaign.id": {"file": "dimensions", "category": "dimension"},
                    "metric.clicks": {"file": "metrics", "category": "metric"},
                },
            },
            indent=2,
            sort_keys=True,
        )
    )
    meta = {
        "schema_version": 1,
        "parsed_at": "2026-01-01T00:00:00Z",
        "generated_at": "2026-01-01T00:00:00Z",
        "generator_version": "test",
        "source_commit": "test",
        "source_files_sha256": {
            "amazon_ads_v1_dimensions.json": "x",
            "amazon_ads_v1_metrics.json": "y",
        },
        "output_files_sha256": {
            "dimensions.json": hashlib.sha256(dims_bytes).hexdigest(),
            "metrics.json": hashlib.sha256(metrics_bytes).hexdigest(),
        },
    }
    (tmp_path / "catalog_meta.json").write_text(json.dumps(meta, indent=2, sort_keys=True))
    return tmp_path


# ---------- C.1: lazy load + explicit filenames -----------------------------


def test_no_io_at_import(monkeypatch):
    """Importing the loader module must not open any files."""
    sys.modules.pop("amazon_ads_mcp.tools.report_fields_v1_catalog", None)

    opened: list[str] = []
    real_open = builtins.open

    def spy_open(path, *args, **kwargs):
        opened.append(str(path))
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", spy_open)

    import amazon_ads_mcp.tools.report_fields_v1_catalog  # noqa: F401

    # Filter to catalog-specific paths; other modules may legitimately open
    # files during import (and the monkeypatch is process-wide while import
    # runs). The loader specifically must not open resources/adsv1/*.
    catalog_opens = [p for p in opened if "resources/adsv1" in p or "adsv1_specs" in p]
    assert catalog_opens == [], f"loader opened catalog files at import: {catalog_opens}"


def test_opens_only_named_files_subset(fresh_loader, happy_catalog_dir, monkeypatch):
    """On first query, opened paths are a subset of the 4 named files; never *.tmp."""
    fresh_loader.set_catalog_dir(happy_catalog_dir)

    opened: list[str] = []
    real_open = builtins.open

    def spy_open(path, *args, **kwargs):
        opened.append(str(path))
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", spy_open)

    fresh_loader.load_catalog()

    catalog_opens = [p for p in opened if str(happy_catalog_dir) in p]
    allowed = {
        str(happy_catalog_dir / "dimensions.json"),
        str(happy_catalog_dir / "metrics.json"),
        str(happy_catalog_dir / "index.json"),
        str(happy_catalog_dir / "catalog_meta.json"),
    }
    for path in catalog_opens:
        assert path in allowed, f"unexpected open: {path}"
        assert ".tmp" not in path, f"loader opened a .tmp file: {path}"


def test_ignores_stray_and_tmp_files(fresh_loader, happy_catalog_dir, monkeypatch):
    """Stray stray.json and dimensions.json.tmp next to catalog files are never opened."""
    (happy_catalog_dir / "stray.json").write_text("{}")
    (happy_catalog_dir / "dimensions.json.tmp").write_text("garbage")

    fresh_loader.set_catalog_dir(happy_catalog_dir)

    opened: list[str] = []
    real_open = builtins.open

    def spy_open(path, *args, **kwargs):
        opened.append(str(path))
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", spy_open)

    fresh_loader.load_catalog()

    catalog_opens = [p for p in opened if str(happy_catalog_dir) in p]
    for path in catalog_opens:
        filename = Path(path).name
        assert filename != "stray.json", f"loader opened stray file: {path}"
        assert not filename.endswith(".tmp"), f"loader opened .tmp file: {path}"


# ---------- C.2: commit-signal verification ---------------------------------


def test_missing_catalog_meta_fails_closed(fresh_loader, tmp_path: Path):
    # Build a dir with dimensions+metrics but NO catalog_meta.json.
    (tmp_path / "dimensions.json").write_text("[]")
    (tmp_path / "metrics.json").write_text("[]")
    (tmp_path / "index.json").write_text('{"schema_version": 1, "fields": {}}')

    fresh_loader.set_catalog_dir(tmp_path)

    with pytest.raises(fresh_loader.CatalogSchemaError) as excinfo:
        fresh_loader.load_catalog()
    assert "catalog_meta" in str(excinfo.value).lower()


def test_old_runtime_new_catalog_fails_closed(fresh_loader, happy_catalog_dir):
    """schema_version higher than runtime SUPPORTED → fail closed."""
    meta_path = happy_catalog_dir / "catalog_meta.json"
    meta = json.loads(meta_path.read_text())
    meta["schema_version"] = 99
    meta_path.write_text(json.dumps(meta, indent=2, sort_keys=True))

    fresh_loader.set_catalog_dir(happy_catalog_dir)
    with pytest.raises(fresh_loader.CatalogSchemaError) as excinfo:
        fresh_loader.load_catalog()
    assert "schema_version" in str(excinfo.value)


def test_new_runtime_old_catalog_fails_closed(fresh_loader, happy_catalog_dir):
    """schema_version lower than runtime SUPPORTED → also fail closed (strict, both directions)."""
    meta_path = happy_catalog_dir / "catalog_meta.json"
    meta = json.loads(meta_path.read_text())
    meta["schema_version"] = 0
    meta_path.write_text(json.dumps(meta, indent=2, sort_keys=True))

    fresh_loader.set_catalog_dir(happy_catalog_dir)
    with pytest.raises(fresh_loader.CatalogSchemaError):
        fresh_loader.load_catalog()


def test_interrupted_refresh_detected_by_hash_mismatch(fresh_loader, happy_catalog_dir):
    """Simulate: catalog_meta.json stale from last refresh; dimensions.json
    was overwritten by a new refresh that was interrupted before meta was
    updated. Loader must detect the SHA-256 mismatch."""
    # Mutate dimensions.json so its hash no longer matches meta.output_files_sha256.
    (happy_catalog_dir / "dimensions.json").write_bytes(b"[]\n")

    fresh_loader.set_catalog_dir(happy_catalog_dir)
    with pytest.raises(fresh_loader.CatalogSchemaError) as excinfo:
        fresh_loader.load_catalog()
    msg = str(excinfo.value).lower()
    assert "interrupted" in msg or "hash" in msg or "sha256" in msg


def test_error_code_is_catalog_schema_mismatch(fresh_loader, happy_catalog_dir):
    """Every failure carries ReportFieldsErrorCode.CATALOG_SCHEMA_MISMATCH."""
    (happy_catalog_dir / "dimensions.json").write_bytes(b"[]\n")

    fresh_loader.set_catalog_dir(happy_catalog_dir)
    try:
        fresh_loader.load_catalog()
    except fresh_loader.CatalogSchemaError as exc:
        from amazon_ads_mcp.tools.report_fields_errors import ReportFieldsErrorCode

        assert exc.code == ReportFieldsErrorCode.CATALOG_SCHEMA_MISMATCH
    else:
        pytest.fail("expected CatalogSchemaError")


def test_happy_path_returns_parsed_data(fresh_loader, happy_catalog_dir):
    fresh_loader.set_catalog_dir(happy_catalog_dir)
    bundle = fresh_loader.load_catalog()

    assert bundle["meta"]["schema_version"] == 1
    assert "fields" in bundle["index"]

    dims = fresh_loader.get_dimensions()
    metrics = fresh_loader.get_metrics()
    assert any(r["field_id"] == "campaign.id" for r in dims)
    assert any(r["field_id"] == "metric.clicks" for r in metrics)


def test_single_field_lookup_uses_index(fresh_loader, happy_catalog_dir):
    fresh_loader.set_catalog_dir(happy_catalog_dir)
    record = fresh_loader.lookup_field("metric.clicks")
    assert record is not None
    assert record["category"] == "metric"

    assert fresh_loader.lookup_field("nonexistent.field") is None
