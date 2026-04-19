"""Tests for refresh-time integrity checks (adsv1.md §4.9 + §B.2).

Covers charset enforcement, uniqueness across dimensions+metrics,
reference-existence checks, and required_fields cycle detection. All
checks run at refresh time in CI — never at runtime.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from amazon_ads_mcp.build.integrity import (
    CatalogIntegrityError,
    check_catalog,
)

FIXTURE_DIR = Path(__file__).parent.parent / "fixtures" / "adsv1_catalog_pathological"


def _load(name: str) -> dict:
    return json.loads((FIXTURE_DIR / name).read_text())


def test_valid_catalog_passes():
    check_catalog(_load("valid.json"))


def test_duplicate_field_id_across_dims_and_metrics_fails():
    with pytest.raises(CatalogIntegrityError) as excinfo:
        check_catalog(_load("duplicate_field_id.json"))
    assert "shared.id" in str(excinfo.value)
    assert "duplicate" in str(excinfo.value).lower()


def test_bad_charset_fails():
    """Zero-width space in field_id — caught by charset guard."""
    with pytest.raises(CatalogIntegrityError) as excinfo:
        check_catalog(_load("bad_charset.json"))
    assert "charset" in str(excinfo.value).lower() or "field_id" in str(excinfo.value).lower()


def test_broken_required_ref_fails():
    with pytest.raises(CatalogIntegrityError) as excinfo:
        check_catalog(_load("broken_required_ref.json"))
    assert "nonexistent.field" in str(excinfo.value)


def test_cycle_in_required_fails():
    with pytest.raises(CatalogIntegrityError) as excinfo:
        check_catalog(_load("cycle_in_required.json"))
    assert "cycle" in str(excinfo.value).lower()
    # Either endpoint of the cycle should appear in the message for debuggability.
    msg = str(excinfo.value)
    assert "a.id" in msg or "b.id" in msg


def test_self_reference_is_cycle():
    catalog = {
        "dimensions": [
            {
                "field_id": "x.self",
                "display_name": "X",
                "data_type": "STRING",
                "required_fields": ["x.self"],
                "source": {"md_file": "x.md", "parsed_at": "2026-01-01T00:00:00Z"},
            }
        ],
        "metrics": [],
    }
    with pytest.raises(CatalogIntegrityError) as excinfo:
        check_catalog(catalog)
    assert "cycle" in str(excinfo.value).lower()
