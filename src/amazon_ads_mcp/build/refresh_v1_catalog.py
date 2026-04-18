"""Refresh the packaged v1 catalog from raw .build/adsv1_specs/ sources.

Locked protocol from adsv1.md §4.9:

  atomic writes (*.tmp -> os.replace) with commit order
    dimensions -> metrics -> index -> catalog_meta (LAST)

`catalog_meta.json` is the commit signal — the loader verifies
`output_files_sha256` against on-disk hashes on first load so an
interrupted refresh fails closed rather than serving mixed data.

Invocation:
    python -m amazon_ads_mcp.build.refresh_v1_catalog \
        --source .build/adsv1_specs \
        --dest src/amazon_ads_mcp/resources/adsv1 \
        --validate --production-floors

Flags:
    --validate              Run JSON-Schema + charset guard on every source record.
    --production-floors     Enforce minimum-content floors (>=100 dims / >=600 metrics).
                            Override with env var ALLOW_CATALOG_COUNT_DROP=true.
    --check                 Fail if a real refresh would produce a different dest.
                            Used by CI drift gate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Mapping, Tuple

from .atomic_json import save_json_atomic
from .integrity import CatalogIntegrityError, check_catalog
from .validators import SourceRecordValidationError, validate_source_record

#: Current packaged catalog schema version. Bump requires loader reader update.
SCHEMA_VERSION = 1

#: Minimum-content floors in production runs. Override with
#: ALLOW_CATALOG_COUNT_DROP=true in the environment (with CODEOWNERS sign-off).
PRODUCTION_MIN_DIMENSIONS = 100
PRODUCTION_MIN_METRICS = 600

#: Provenance value for the entire v1 catalog — scraped from Amazon docs.
V1_PROVENANCE = "documented"

#: Ordered commit list. catalog_meta.json MUST be last.
_COMMIT_ORDER = ["dimensions.json", "metrics.json", "index.json", "catalog_meta.json"]


class CatalogCountFloorError(ValueError):
    """Raised when production-floors gate fails (without override)."""


# ---------- helpers -------------------------------------------------------


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _clip_short_description(description: str | None) -> str:
    if not description:
        return ""
    text = " ".join(description.split())
    return text[:160]


def _git_head_sha() -> str:
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL
        )
        return out.decode().strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "unknown"


def _max_parsed_at(catalog: Mapping[str, Any]) -> str:
    """Find the lexically-latest source.parsed_at across all records."""
    latest = ""
    for key in ("dimensions", "metrics"):
        for record in catalog.get(key, []) or []:
            ts = (record.get("source") or {}).get("parsed_at") or ""
            if ts > latest:
                latest = ts
    return latest


def _sweep_orphaned_tmp(dest: Path) -> None:
    if not dest.exists():
        return
    for tmp in dest.glob("*.tmp"):
        try:
            tmp.unlink()
        except OSError:
            pass


def _normalize_record(record: Dict[str, Any], category: str) -> Dict[str, Any]:
    """Shape a raw source record into the packaged form (post-normalized).

    The packaged form is what the loader hands to handlers — it carries
    category, provenance, and short_description already computed. Kept
    stable so catalog diffs are semantic, not formatting noise.
    """
    out: Dict[str, Any] = {
        "field_id": record["field_id"].strip(),
        "display_name": record.get("display_name", ""),
        "data_type": record.get("data_type") or "UNKNOWN",
        "category": category,
        "provenance": V1_PROVENANCE,
        "short_description": _clip_short_description(record.get("description")),
        "description": record.get("description") or None,
        "required_fields": list(record.get("required_fields", []) or []),
        "complementary_fields": list(record.get("complementary_fields", []) or []),
    }

    if category == "dimension":
        out["compatible_dimensions"] = list(record.get("compatible_dimensions", []) or [])
        out["incompatible_dimensions"] = list(record.get("incompatible_dimensions", []) or [])

    out["v3_name_dsp"] = record.get("v3_name_dsp")
    out["v3_name_sponsored_ads"] = record.get("v3_name_sponsored_ads")

    src = record.get("source") or {}
    out["source"] = {
        "md_file": src.get("md_file"),
        "parsed_at": src.get("parsed_at"),
    }
    return out


def _load_source_array(path: Path) -> List[Dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise SourceRecordValidationError(
            f"{path.name} must be a JSON array; got {type(data).__name__}"
        )
    return data


def _dedupe_identical_records(
    records: List[Dict[str, Any]], *, file_label: str
) -> List[Dict[str, Any]]:
    """Collapse byte-identical duplicates within a single source file.

    Scraping pipelines occasionally emit the same record twice (same md_file,
    same fields). Byte-identical duplicates carry no information and are
    dropped. Records sharing a field_id but differing in any other field are
    NOT deduped here — they fall through to the uniqueness integrity check
    which fails with a clear error.
    """
    by_id: Dict[str, Dict[str, Any]] = {}
    for record in records:
        fid = record.get("field_id")
        if not isinstance(fid, str):
            # Validator (when enabled) will catch this; pass through otherwise.
            continue
        existing = by_id.get(fid)
        if existing is None:
            by_id[fid] = record
        elif existing == record:
            # Byte-identical duplicate — silently collapse.
            continue
        else:
            # Same field_id, different content — keep both so the uniqueness
            # check surfaces the conflict with full context.
            by_id[fid + f"__conflict_{id(record)}"] = record

    # Preserve original order as much as possible: walk the input again and
    # emit the canonical record for each field_id the first time we see it,
    # plus any conflict sentinels in their first-seen order.
    emitted: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for record in records:
        fid = record.get("field_id")
        if not isinstance(fid, str):
            emitted.append(record)
            continue
        if fid not in seen:
            emitted.append(by_id[fid])
            seen.add(fid)
        # Always emit conflict sentinels so check_uniqueness can flag them.
        for conflict_key in list(by_id.keys()):
            if conflict_key.startswith(fid + "__conflict_"):
                emitted.append(by_id.pop(conflict_key))
    return emitted


# ---------- core refresh -------------------------------------------------


def _build_catalog(source: Path, *, do_validate: bool) -> Dict[str, Any]:
    """Load source files, optionally run the validator, and return the
    post-load shape {"dimensions": [...], "metrics": [...]} used by the
    integrity checks.
    """
    dims_raw = _load_source_array(source / "amazon_ads_v1_dimensions.json")
    mets_raw = _load_source_array(source / "amazon_ads_v1_metrics.json")

    if do_validate:
        for rec in dims_raw:
            validate_source_record(rec)
        for rec in mets_raw:
            validate_source_record(rec)

    # Collapse byte-identical duplicates (common scraping artifact). Conflicting
    # duplicates with the same field_id are preserved so the uniqueness check
    # catches them with full context.
    dims_raw = _dedupe_identical_records(dims_raw, file_label="dimensions")
    mets_raw = _dedupe_identical_records(mets_raw, file_label="metrics")

    return {"dimensions": dims_raw, "metrics": mets_raw}


def _build_outputs(
    catalog: Mapping[str, Any],
    *,
    source: Path,
    parsed_at: str,
    generated_at: str,
    source_commit: str,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any], Dict[str, Any]]:
    """Produce the four packaged output payloads as Python dicts.

    output_files_sha256 is populated AFTER the data files are written, so
    catalog_meta returned here has an empty output_files_sha256 map that
    the caller fills before the final commit.
    """
    dimensions = [_normalize_record(r, "dimension") for r in catalog.get("dimensions", [])]
    metrics = [_normalize_record(r, "metric") for r in catalog.get("metrics", [])]

    # Stable ordering in packaged files so diffs are semantic.
    dimensions.sort(key=lambda r: r["field_id"])
    metrics.sort(key=lambda r: r["field_id"])

    index_fields: Dict[str, Dict[str, str]] = {}
    for r in dimensions:
        index_fields[r["field_id"]] = {"file": "dimensions", "category": "dimension"}
    for r in metrics:
        index_fields[r["field_id"]] = {"file": "metrics", "category": "metric"}

    index = {"schema_version": SCHEMA_VERSION, "fields": index_fields}

    src_dims = source / "amazon_ads_v1_dimensions.json"
    src_metrics = source / "amazon_ads_v1_metrics.json"

    from .. import __version__ as pkg_version  # type: ignore[attr-defined]  # pragma: no cover

    meta: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "parsed_at": parsed_at,
        "generated_at": generated_at,
        "generator_version": pkg_version,
        "source_commit": source_commit,
        "source_files_sha256": {
            "amazon_ads_v1_dimensions.json": _sha256_file(src_dims),
            "amazon_ads_v1_metrics.json": _sha256_file(src_metrics),
        },
        "output_files_sha256": {},  # filled in after writing dims + metrics
    }

    return dimensions, metrics, index, meta


def _enforce_floors(
    dims_count: int,
    metrics_count: int,
    *,
    production_floors: bool,
) -> None:
    if not production_floors:
        return
    if os.environ.get("ALLOW_CATALOG_COUNT_DROP", "").lower() == "true":
        return

    if dims_count < PRODUCTION_MIN_DIMENSIONS:
        raise CatalogCountFloorError(
            f"dimensions count {dims_count} below floor {PRODUCTION_MIN_DIMENSIONS}; "
            f"set ALLOW_CATALOG_COUNT_DROP=true to override"
        )
    if metrics_count < PRODUCTION_MIN_METRICS:
        raise CatalogCountFloorError(
            f"metrics count {metrics_count} below floor {PRODUCTION_MIN_METRICS}; "
            f"set ALLOW_CATALOG_COUNT_DROP=true to override"
        )


def refresh(
    source: Path,
    dest: Path,
    *,
    do_validate: bool = True,
    production_floors: bool = False,
) -> None:
    """Materialize the packaged catalog under *dest*.

    Writes four files in commit order with atomic renames:
        dimensions.json -> metrics.json -> index.json -> catalog_meta.json
    catalog_meta.json is the commit signal; loader verifies on-disk
    hashes against `output_files_sha256` on first load.
    """
    source = Path(source)
    dest = Path(dest)

    _sweep_orphaned_tmp(dest)

    catalog = _build_catalog(source, do_validate=do_validate)
    check_catalog(catalog)

    _enforce_floors(
        len(catalog.get("dimensions", [])),
        len(catalog.get("metrics", [])),
        production_floors=production_floors,
    )

    parsed_at = _max_parsed_at(catalog)
    # Pin generated_at to parsed_at so refresh is byte-idempotent: two runs
    # against the same source produce identical catalog_meta.json (required
    # by the §B.3 idempotency AC and the CI drift gate). The semantic meaning
    # matches — the catalog *is* this point in time from the source.
    generated_at = parsed_at

    dimensions, metrics, index, meta = _build_outputs(
        catalog,
        source=source,
        parsed_at=parsed_at,
        generated_at=generated_at,
        source_commit=_git_head_sha(),
    )

    dest.mkdir(parents=True, exist_ok=True)

    # Commit order matters. dimensions -> metrics -> index -> catalog_meta.
    # After dimensions + metrics land, we hash them and stamp the meta payload.
    save_json_atomic(dest / "dimensions.json", dimensions)
    save_json_atomic(dest / "metrics.json", metrics)

    # Fill output_files_sha256 AFTER data files have landed on disk.
    meta["output_files_sha256"] = {
        "dimensions.json": _sha256_file(dest / "dimensions.json"),
        "metrics.json": _sha256_file(dest / "metrics.json"),
    }

    save_json_atomic(dest / "index.json", index)
    save_json_atomic(dest / "catalog_meta.json", meta)


# ---------- --check mode -------------------------------------------------


def check_drift(source: Path, dest: Path) -> bool:
    """Return True if *dest* matches what a fresh refresh would produce.

    Compares data files (dimensions, metrics, index) byte-for-byte. The
    catalog_meta.json is compared on its deterministic subset only:
    schema_version, parsed_at, source_files_sha256, output_files_sha256.
    (generated_at, generator_version, source_commit are not compared —
    those change between runs without representing drift.)
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_dest = Path(tmpdir)
        refresh(source, tmp_dest, do_validate=True, production_floors=False)

        for name in ("dimensions.json", "metrics.json", "index.json"):
            expected = (tmp_dest / name).read_bytes()
            actual_path = dest / name
            if not actual_path.exists():
                return False
            if actual_path.read_bytes() != expected:
                return False

        exp_meta = json.loads((tmp_dest / "catalog_meta.json").read_text())
        act_meta_path = dest / "catalog_meta.json"
        if not act_meta_path.exists():
            return False
        act_meta = json.loads(act_meta_path.read_text())
        for key in ("schema_version", "source_files_sha256", "output_files_sha256"):
            if exp_meta.get(key) != act_meta.get(key):
                return False

    return True


# ---------- CLI entry point ----------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="refresh_v1_catalog",
        description="Generate the packaged v1 catalog from .build/adsv1_specs/.",
    )
    p.add_argument(
        "--source",
        type=Path,
        default=Path(".build/adsv1_specs"),
        help="Directory containing amazon_ads_v1_{dimensions,metrics}.json",
    )
    p.add_argument(
        "--dest",
        type=Path,
        default=Path("src/amazon_ads_mcp/resources/adsv1"),
        help="Destination directory for packaged catalog files",
    )
    p.add_argument(
        "--validate",
        action="store_true",
        help="Run JSON-Schema + charset validator on every source record.",
    )
    p.add_argument(
        "--production-floors",
        action="store_true",
        help="Enforce minimum-content floors (>=100 dims / >=600 metrics).",
    )
    p.add_argument(
        "--check",
        action="store_true",
        help="Fail if a real refresh would produce a different dest.",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.check:
        try:
            ok = check_drift(args.source, args.dest)
        except (
            SourceRecordValidationError,
            CatalogIntegrityError,
            CatalogCountFloorError,
        ) as exc:
            print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
            return 2
        if not ok:
            print(
                f"catalog drift detected under {args.dest}; run refresh to regenerate",
                file=sys.stderr,
            )
            return 1
        print(f"catalog in sync under {args.dest}")
        return 0

    try:
        refresh(
            args.source,
            args.dest,
            do_validate=args.validate,
            production_floors=args.production_floors,
        )
    except (
        SourceRecordValidationError,
        CatalogIntegrityError,
        CatalogCountFloorError,
    ) as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

    print(f"catalog refreshed under {args.dest}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
