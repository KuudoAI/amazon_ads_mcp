"""Tests for the v1 catalog refresh CLI (adsv1.md §B.3 + §4.9).

Covers:
- Happy path against the 5-record source fixture.
- `--check` mode (no drift / drift).
- Idempotency: running refresh twice produces zero diff.
- Orphaned `*.tmp` sweep at start.
- Commit order: meta.json written LAST; crash before meta leaves it absent.
- Minimum-content floors: --production-floors flag gates the check;
  ALLOW_CATALOG_COUNT_DROP env var is the override.
- catalog_meta.json carries source_files_sha256 AND output_files_sha256.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from amazon_ads_mcp.build import refresh_v1_catalog as refresh_mod

FIXTURE_DIR = Path(__file__).parent.parent / "fixtures"
SOURCE_VALID = FIXTURE_DIR / "adsv1_source_valid"


def _run_cli(source: Path, dest: Path, *extra: str) -> subprocess.CompletedProcess:
    """Invoke the CLI as `python -m amazon_ads_mcp.build.refresh_v1_catalog`."""
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "amazon_ads_mcp.build.refresh_v1_catalog",
            "--source",
            str(source),
            "--dest",
            str(dest),
            *extra,
        ],
        capture_output=True,
        text=True,
    )


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# ---------- happy path -------------------------------------------------------


def test_happy_path_produces_four_files(tmp_path: Path):
    dest = tmp_path / "dest"
    refresh_mod.refresh(SOURCE_VALID, dest)
    for name in ("dimensions.json", "metrics.json", "index.json", "catalog_meta.json"):
        assert (dest / name).exists(), f"missing {name}"


def test_catalog_meta_carries_sha256_manifest(tmp_path: Path):
    dest = tmp_path / "dest"
    refresh_mod.refresh(SOURCE_VALID, dest)
    meta = json.loads((dest / "catalog_meta.json").read_text())

    assert meta["schema_version"] == 1
    assert "parsed_at" in meta
    assert "generated_at" in meta
    assert "source_commit" in meta

    assert set(meta["source_files_sha256"].keys()) == {
        "amazon_ads_v1_dimensions.json",
        "amazon_ads_v1_metrics.json",
    }
    assert set(meta["output_files_sha256"].keys()) == {
        "dimensions.json",
        "metrics.json",
    }

    # output_files_sha256 must match actual on-disk hashes of the packaged outputs.
    assert meta["output_files_sha256"]["dimensions.json"] == _sha256_file(dest / "dimensions.json")
    assert meta["output_files_sha256"]["metrics.json"] == _sha256_file(dest / "metrics.json")


def test_index_routes_to_correct_files(tmp_path: Path):
    dest = tmp_path / "dest"
    refresh_mod.refresh(SOURCE_VALID, dest)
    index = json.loads((dest / "index.json").read_text())

    assert index["schema_version"] == 1
    assert index["fields"]["metric.clicks"] == {"file": "metrics", "category": "metric"}
    assert index["fields"]["campaign.id"] == {"file": "dimensions", "category": "dimension"}


# ---------- idempotency ------------------------------------------------------


def test_idempotent_two_runs_produce_zero_diff(tmp_path: Path):
    dest = tmp_path / "dest"
    refresh_mod.refresh(SOURCE_VALID, dest)

    first = {p.name: p.read_bytes() for p in sorted(dest.glob("*.json"))}

    refresh_mod.refresh(SOURCE_VALID, dest)

    second = {p.name: p.read_bytes() for p in sorted(dest.glob("*.json"))}

    assert first == second


# ---------- --check mode -----------------------------------------------------


def test_check_mode_passes_when_in_sync(tmp_path: Path):
    dest = tmp_path / "dest"
    refresh_mod.refresh(SOURCE_VALID, dest)

    # Now run --check via subprocess — exit code 0 means in sync.
    result = _run_cli(SOURCE_VALID, dest, "--check")
    assert result.returncode == 0, result.stderr


def test_check_mode_fails_on_drift(tmp_path: Path):
    dest = tmp_path / "dest"
    refresh_mod.refresh(SOURCE_VALID, dest)

    # Corrupt one output file.
    (dest / "dimensions.json").write_text("[]\n")

    result = _run_cli(SOURCE_VALID, dest, "--check")
    assert result.returncode != 0
    assert "drift" in (result.stderr + result.stdout).lower()


# ---------- orphan sweep -----------------------------------------------------


def test_orphaned_tmp_files_are_swept(tmp_path: Path):
    dest = tmp_path / "dest"
    dest.mkdir()
    orphan = dest / "dimensions.json.tmp"
    orphan.write_text("garbage")

    refresh_mod.refresh(SOURCE_VALID, dest)

    assert not orphan.exists(), "orphaned .tmp must be swept at refresh start"


# ---------- commit order -----------------------------------------------------


def test_meta_written_last_after_all_data(tmp_path: Path, monkeypatch):
    """If os.replace raises before meta is written, meta.json must be absent."""
    dest = tmp_path / "dest"

    # Count os.replace calls and raise on the 4th (the catalog_meta commit).
    # Commit order: dimensions(1) -> metrics(2) -> index(3) -> catalog_meta(4).
    import amazon_ads_mcp.build.atomic_json as atomic_mod

    call_count = {"n": 0}
    real = atomic_mod.os.replace

    def failing_replace(src, dst):
        call_count["n"] += 1
        if call_count["n"] == 4:
            raise OSError("simulated crash before meta commit")
        return real(src, dst)

    monkeypatch.setattr(atomic_mod.os, "replace", failing_replace)

    with pytest.raises(OSError):
        refresh_mod.refresh(SOURCE_VALID, dest)

    # The first three made it, the fourth did not.
    assert (dest / "dimensions.json").exists()
    assert (dest / "metrics.json").exists()
    assert (dest / "index.json").exists()
    assert not (dest / "catalog_meta.json").exists(), (
        "catalog_meta.json must be the LAST file written — when its commit "
        "fails, the file must not be present"
    )


# ---------- content floors ---------------------------------------------------


def test_fixture_run_does_not_enforce_floors(tmp_path: Path):
    """Without --production-floors, small fixtures pass."""
    dest = tmp_path / "dest"
    # No --production-floors, tiny fixture (3 dims, 2 metrics) → passes.
    refresh_mod.refresh(SOURCE_VALID, dest, production_floors=False)


def test_production_floors_reject_small_catalog(tmp_path: Path, monkeypatch):
    """With --production-floors, the 3/2 fixture fails the 100/600 floor."""
    monkeypatch.delenv("ALLOW_CATALOG_COUNT_DROP", raising=False)
    dest = tmp_path / "dest"
    with pytest.raises(refresh_mod.CatalogCountFloorError):
        refresh_mod.refresh(SOURCE_VALID, dest, production_floors=True)


def test_production_floors_with_override_env_passes(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ALLOW_CATALOG_COUNT_DROP", "true")
    dest = tmp_path / "dest"
    # Even with production floors on, the env override lets it through.
    refresh_mod.refresh(SOURCE_VALID, dest, production_floors=True)


# ---------- negative path ----------------------------------------------------


# ---------- dedupe of byte-identical scraping duplicates -------------------


def test_byte_identical_scraping_duplicates_collapse(tmp_path: Path):
    """Two byte-identical records in one file → collapse silently, no failure.

    Real source data (.build/adsv1_specs/amazon_ads_v1_dimensions.json) has
    `deal.type` emitted twice with identical content. That's a scraping
    artifact; the CLI dedupes it rather than failing.
    """
    source = tmp_path / "src"
    source.mkdir()
    dup = {
        "field_id": "deal.type",
        "display_name": "Deal type",
        "data_type": "STRING",
        "required_fields": [],
        "source": {"md_file": "x.md", "parsed_at": "2026-01-01T00:00:00Z"},
    }
    (source / "amazon_ads_v1_dimensions.json").write_text(json.dumps([dup, dup]))
    (source / "amazon_ads_v1_metrics.json").write_text("[]")

    dest = tmp_path / "dest"
    refresh_mod.refresh(source, dest, do_validate=True, production_floors=False)

    dims = json.loads((dest / "dimensions.json").read_text())
    assert len(dims) == 1, "byte-identical scraping duplicate must collapse to one"


def test_conflicting_same_field_id_still_fails(tmp_path: Path):
    """Two records with the same field_id but different content → hard fail."""
    source = tmp_path / "src"
    source.mkdir()
    a = {
        "field_id": "deal.type",
        "display_name": "Deal type",
        "data_type": "STRING",
        "required_fields": [],
        "source": {"md_file": "x.md", "parsed_at": "2026-01-01T00:00:00Z"},
    }
    b = {**a, "display_name": "Deal KIND (conflict)"}
    (source / "amazon_ads_v1_dimensions.json").write_text(json.dumps([a, b]))
    (source / "amazon_ads_v1_metrics.json").write_text("[]")

    dest = tmp_path / "dest"
    with pytest.raises(refresh_mod.CatalogIntegrityError):
        refresh_mod.refresh(source, dest, do_validate=True, production_floors=False)


def test_corrupted_source_exits_non_zero(tmp_path: Path):
    """Pathological fixture → specific error class printed, non-zero exit."""
    bad_source = tmp_path / "bad"
    bad_source.mkdir()
    # Put malformed source files in.
    (bad_source / "amazon_ads_v1_dimensions.json").write_text('[{"not": "valid"}]')
    (bad_source / "amazon_ads_v1_metrics.json").write_text("[]")

    dest = tmp_path / "dest"
    result = _run_cli(bad_source, dest, "--validate")
    assert result.returncode != 0
    combined = result.stderr + result.stdout
    # The error class name must appear so operators can grep for it.
    assert "SourceRecordValidationError" in combined or "schema" in combined.lower()
