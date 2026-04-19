"""Source-record validator for .build/adsv1_specs/ JSON records.

Combines JSON Schema validation with a post-schema charset guard. The schema
lives at scripts/schemas/adsv1_catalog.schema.json at the repo root.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Mapping

import jsonschema
from jsonschema import Draft202012Validator

#: Locked charset for field_id — ASCII alphanumerics, dot, underscore, hyphen.
#: Catches zero-width spaces, smart quotes, whitespace, and other scraping artifacts.
FIELD_ID_CHARSET = re.compile(r"^[a-zA-Z0-9._-]+$")


class SourceRecordValidationError(ValueError):
    """Raised when a source record fails schema validation or charset guards."""


def _repo_root() -> Path:
    """Locate the repo root by walking up from this module until we find pyproject.toml."""
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "pyproject.toml").exists():
            return parent
    raise RuntimeError("could not locate repo root from build/validators.py")


@lru_cache(maxsize=1)
def _schema() -> Mapping[str, Any]:
    path = _repo_root() / "scripts" / "schemas" / "adsv1_catalog.schema.json"
    return json.loads(path.read_text())


@lru_cache(maxsize=1)
def _validator() -> Draft202012Validator:
    return Draft202012Validator(_schema())


def validate_source_record(record: Mapping[str, Any]) -> None:
    """Validate a single source record.

    Raises SourceRecordValidationError on any schema violation OR on a
    field_id that contains characters outside FIELD_ID_CHARSET.
    """
    field_id = record.get("field_id") if isinstance(record, Mapping) else None

    try:
        _validator().validate(record)
    except jsonschema.ValidationError as exc:
        ident = field_id if field_id is not None else "<no field_id>"
        raise SourceRecordValidationError(
            f"schema violation for {ident!r}: {exc.message}"
        ) from exc

    if not isinstance(field_id, str) or not FIELD_ID_CHARSET.match(field_id):
        raise SourceRecordValidationError(
            f"charset violation: field_id {field_id!r} contains characters outside "
            f"[a-zA-Z0-9._-]"
        )
