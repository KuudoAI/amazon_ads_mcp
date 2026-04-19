"""Tests for the adsv1 source-record JSON Schema + post-schema charset check.

The schema lives at scripts/schemas/adsv1_catalog.schema.json and enforces the
minimum required keys on every raw record from .build/adsv1_specs/. The charset
guard catches scraping artifacts (zero-width spaces, smart quotes, whitespace)
that schema-level validation alone misses.
"""

import json
from pathlib import Path

import pytest

from amazon_ads_mcp.build.validators import (
    SourceRecordValidationError,
    validate_source_record,
)

FIXTURE_DIR = Path(__file__).parent.parent / "fixtures" / "adsv1_sources"


def _load(name: str) -> dict:
    return json.loads((FIXTURE_DIR / name).read_text())


def test_valid_minimal_record_passes():
    validate_source_record(_load("valid_minimal.json"))


def test_missing_field_id_fails():
    with pytest.raises(SourceRecordValidationError):
        validate_source_record(_load("missing_field_id.json"))


def test_missing_parsed_at_fails():
    with pytest.raises(SourceRecordValidationError):
        validate_source_record(_load("missing_parsed_at.json"))


def test_zero_width_space_in_field_id_fails():
    """Scraping artifact: zero-width space rejected by charset guard, not schema."""
    with pytest.raises(SourceRecordValidationError) as excinfo:
        validate_source_record(_load("bad_charset.json"))
    assert "charset" in str(excinfo.value).lower() or "field_id" in str(excinfo.value).lower()


def test_whitespace_in_field_id_fails():
    with pytest.raises(SourceRecordValidationError):
        validate_source_record(_load("whitespace_in_id.json"))


def test_error_type_carries_field_id_when_available():
    """When the record has a field_id, the error message should mention it."""
    with pytest.raises(SourceRecordValidationError) as excinfo:
        validate_source_record(_load("whitespace_in_id.json"))
    assert "metric .clicks" in str(excinfo.value)
