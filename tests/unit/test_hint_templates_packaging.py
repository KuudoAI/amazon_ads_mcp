"""Round 13 B-8 — packaging guard for canonical hint-template spec.

The spec file at ``openbridge-mcp/schemas/jsonschema_error_codes.json``
must ship with the Ads wheel (under ``resources/contract/``) so the
production container has a guaranteed source of hint templates. Without
it, ``_HINT_TEMPLATES`` is empty and ``SCHEMA_*`` envelopes fall back
to generic boilerplate — defeating the whole point of Phase B-8.

These tests pin the contract:

  1. The packaged copy exists at the expected path.
  2. ``_HINT_TEMPLATES`` is non-empty at import time.
  3. The packaged copy doesn't drift from the canonical openbridge
     copy (when both are available — i.e. dev workstations).
"""

from __future__ import annotations

import json
import pathlib

import pytest


PACKAGED_PATH = (
    pathlib.Path(__file__).resolve().parent.parent.parent
    / "src"
    / "amazon_ads_mcp"
    / "resources"
    / "contract"
    / "jsonschema_error_codes.json"
)

CANONICAL_PATH = (
    pathlib.Path(__file__).resolve().parent.parent.parent.parent
    / "openbridge-mcp"
    / "schemas"
    / "jsonschema_error_codes.json"
)


def test_packaged_spec_file_exists() -> None:
    """Wheel must include the canonical spec under
    ``src/amazon_ads_mcp/resources/contract/jsonschema_error_codes.json``.
    Catches a contributor who forgets to update ``pyproject.toml``'s
    ``[[tool.poetry.include]]`` block."""
    assert PACKAGED_PATH.is_file(), (
        f"Canonical spec missing at {PACKAGED_PATH}. "
        f"Copy openbridge-mcp/schemas/jsonschema_error_codes.json into "
        f"src/amazon_ads_mcp/resources/contract/ and add a "
        f"[[tool.poetry.include]] entry to pyproject.toml."
    )


def test_packaged_spec_file_is_valid_json_with_mapping() -> None:
    raw = json.loads(PACKAGED_PATH.read_text(encoding="utf-8"))
    assert isinstance(raw.get("mapping"), dict) and raw["mapping"], (
        "Packaged spec must have a non-empty 'mapping' object"
    )
    assert isinstance(raw.get("fallback"), dict), (
        "Packaged spec must have a 'fallback' object"
    )


def test_hint_templates_loads_non_empty_at_import() -> None:
    """``_HINT_TEMPLATES`` is a process-lifetime constant. It MUST be
    non-empty in production — the whole hint-population path depends
    on it. Empty == packaging regression."""
    from amazon_ads_mcp.middleware.schema_validation import _HINT_TEMPLATES

    assert _HINT_TEMPLATES, (
        "_HINT_TEMPLATES is empty at import time. The packaged spec "
        f"file at {PACKAGED_PATH} did not load. Check pyproject.toml "
        "include block and the loader's search path."
    )
    assert "SCHEMA_TYPE_MISMATCH" in _HINT_TEMPLATES, (
        "Loaded templates missing SCHEMA_TYPE_MISMATCH"
    )
    assert "SCHEMA_VALIDATION_FAILED" in _HINT_TEMPLATES, (
        "Loaded templates missing SCHEMA_VALIDATION_FAILED fallback"
    )


def test_packaged_spec_does_not_drift_from_canonical() -> None:
    """Dev workstations have both copies — packaged AND canonical.
    They MUST be byte-identical so the wheel ships truth, not a
    snapshot. CI catches drift; production has only the packaged
    copy and trusts it. Skipped when canonical isn't checked out
    (e.g. CI pipelines that don't pull the openbridge-mcp repo)."""
    if not CANONICAL_PATH.is_file():
        pytest.skip("openbridge-mcp/schemas/ not present in this checkout")
    packaged = PACKAGED_PATH.read_text(encoding="utf-8")
    canonical = CANONICAL_PATH.read_text(encoding="utf-8")
    assert packaged == canonical, (
        f"Packaged spec at {PACKAGED_PATH} has drifted from canonical "
        f"at {CANONICAL_PATH}. Re-copy: "
        f"`cp {CANONICAL_PATH} {PACKAGED_PATH}`"
    )
