"""Phase A tests for build-time PascalCase ``arg_aliases`` auto-emission.

The pure function under test lives in ``.build/scripts/process_openapi_specs.py``
and is named ``derive_pascal_case_arg_aliases``. It takes an OpenAPI
operation dict plus the existing ``arg_aliases`` list and returns the
merged list, applying:

- Pure case-fix emission (e.g. ``MarketplaceIds`` → ``marketplaceIds``)
  for every camelCase param whose canonical starts lowercase
- Skip when canonical already starts uppercase (``IsISPU`` stays put —
  no PascalCase variant to emit)
- Top-level body-schema properties get aliases too (``$ref`` resolved)
- Nested object properties are NOT aliased (top-level only)
- Dedup on exact ``{from, to}`` pair (do-not-duplicate)
- Skip emission when any existing rule already claims the same ``from``
  with a different ``to`` or a ``wrap`` field (do-not-collide;
  hand-authored intent always wins)

The function is testable without invoking ``main()`` so the build
pipeline doesn't have to run.

Note: ``.build/`` is private build infrastructure and stays uncommitted.
This test file lives under ``tests/unit/`` (committable) and imports
from ``.build/scripts`` via a path-aware loader.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


def _load_build_script() -> object:
    """Load ``.build/scripts/process_openapi_specs.py`` as a module without
    going through Python's normal import mechanism (``.build/`` is not on
    ``sys.path`` and is intentionally not a package).
    """
    repo_root = Path(__file__).resolve().parents[2]
    script_path = repo_root / ".build" / "scripts" / "process_openapi_specs.py"
    if not script_path.exists():
        pytest.skip(f"build script not present at {script_path}")
    # spec_patches imports from .build/spec_patches via sys.path hack at the
    # top of the script — make .build/ importable for this load.
    build_dir = repo_root / ".build"
    if str(build_dir) not in sys.path:
        sys.path.insert(0, str(build_dir))
    spec = importlib.util.spec_from_file_location(
        "build_process_openapi_specs", script_path
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def build_script():
    return _load_build_script()


# ---------------------------------------------------------------------------
# Function surface
# ---------------------------------------------------------------------------


def test_module_exposes_derive_pascal_case_arg_aliases(build_script):
    assert hasattr(build_script, "derive_pascal_case_arg_aliases")


# ---------------------------------------------------------------------------
# Query / path / header parameters
# ---------------------------------------------------------------------------


def test_camel_case_query_param_emits_pascal_alias(build_script):
    op = {
        "parameters": [
            {"name": "marketplaceIds", "in": "query", "schema": {"type": "array"}},
        ],
    }
    result = build_script.derive_pascal_case_arg_aliases(op, [])
    assert result == [{"from": "MarketplaceIds", "to": "marketplaceIds"}]


def test_finances_v2_posted_after_emits(build_script):
    op = {
        "parameters": [
            {"name": "postedAfter", "in": "query", "schema": {"type": "string"}},
            {"name": "postedBefore", "in": "query", "schema": {"type": "string"}},
        ],
    }
    result = build_script.derive_pascal_case_arg_aliases(op, [])
    pairs = {(a["from"], a["to"]) for a in result}
    assert ("PostedAfter", "postedAfter") in pairs
    assert ("PostedBefore", "postedBefore") in pairs


def test_canonical_starting_uppercase_is_skipped(build_script):
    """A param like ``IsISPU`` already starts uppercase — the spec's
    canonical IS the PascalCase form, so emitting a `from: IsISPU,
    to: IsISPU` rule would be a no-op at best and a same-`from` collision
    at worst. Skip it entirely.
    """
    op = {
        "parameters": [
            {"name": "IsISPU", "in": "query", "schema": {"type": "boolean"}},
        ],
    }
    result = build_script.derive_pascal_case_arg_aliases(op, [])
    assert result == []


def test_path_and_header_params_also_get_aliases(build_script):
    op = {
        "parameters": [
            {"name": "campaignId", "in": "path", "schema": {"type": "string"}},
            {"name": "amazonAdvertisingApiClientId", "in": "header", "schema": {"type": "string"}},
        ],
    }
    result = build_script.derive_pascal_case_arg_aliases(op, [])
    pairs = {(a["from"], a["to"]) for a in result}
    assert ("CampaignId", "campaignId") in pairs
    assert ("AmazonAdvertisingApiClientId", "amazonAdvertisingApiClientId") in pairs


# ---------------------------------------------------------------------------
# Request body schema
# ---------------------------------------------------------------------------


def test_top_level_body_properties_get_aliases(build_script):
    op = {
        "requestBody": {
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "campaignName": {"type": "string"},
                            "dailyBudget": {"type": "number"},
                        },
                    }
                }
            }
        }
    }
    result = build_script.derive_pascal_case_arg_aliases(op, [])
    pairs = {(a["from"], a["to"]) for a in result}
    assert ("CampaignName", "campaignName") in pairs
    assert ("DailyBudget", "dailyBudget") in pairs


def test_nested_object_properties_are_not_aliased(build_script):
    """Top-level only. Over-aliasing nested fields is the easier mistake
    to make and the PascalCase query-key problem rarely surfaces below
    the top level."""
    op = {
        "requestBody": {
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "topLevel": {
                                "type": "object",
                                "properties": {
                                    "nestedField": {"type": "string"},
                                },
                            },
                        },
                    }
                }
            }
        }
    }
    result = build_script.derive_pascal_case_arg_aliases(op, [])
    pairs = {(a["from"], a["to"]) for a in result}
    assert ("TopLevel", "topLevel") in pairs
    assert ("NestedField", "nestedField") not in pairs


def test_body_ref_is_resolved_before_emission(build_script):
    """``$ref`` body schemas must be resolved so aliases reference real
    property names, not the ref token itself."""
    spec = {
        "components": {
            "schemas": {
                "Campaign": {
                    "type": "object",
                    "properties": {
                        "campaignName": {"type": "string"},
                    },
                }
            }
        }
    }
    op = {
        "requestBody": {
            "content": {
                "application/json": {
                    "schema": {"$ref": "#/components/schemas/Campaign"},
                }
            }
        }
    }
    # Pass the spec for $ref resolution
    result = build_script.derive_pascal_case_arg_aliases(op, [], spec=spec)
    pairs = {(a["from"], a["to"]) for a in result}
    assert ("CampaignName", "campaignName") in pairs


# ---------------------------------------------------------------------------
# Existing aliases — preservation, dedup, collision
# ---------------------------------------------------------------------------


def test_existing_aliases_are_preserved_unchanged(build_script):
    op = {"parameters": [{"name": "newField", "in": "query"}]}
    existing = [{"from": "ReportId", "to": "reportIds", "wrap": "list"}]
    result = build_script.derive_pascal_case_arg_aliases(op, existing)
    # Hand-authored entry preserved verbatim
    assert {"from": "ReportId", "to": "reportIds", "wrap": "list"} in result
    # Auto-derived entry added
    assert {"from": "NewField", "to": "newField"} in result


def test_dedup_skips_exact_pair_already_present(build_script):
    op = {"parameters": [{"name": "marketplaceIds", "in": "query"}]}
    existing = [{"from": "MarketplaceIds", "to": "marketplaceIds"}]
    result = build_script.derive_pascal_case_arg_aliases(op, existing)
    # Result must contain exactly one entry for the (MarketplaceIds, marketplaceIds) pair
    matching = [a for a in result if a.get("from") == "MarketplaceIds"]
    assert len(matching) == 1


def test_same_from_with_different_to_skips_auto_emission(build_script):
    """Hand-authored ``MarketplaceIds → somethingCustom`` blocks the auto
    case-fix from emitting a competing ``MarketplaceIds → marketplaceIds``
    rule. Hand-authored intent always wins."""
    op = {"parameters": [{"name": "marketplaceIds", "in": "query"}]}
    existing = [{"from": "MarketplaceIds", "to": "somethingCustom"}]
    result = build_script.derive_pascal_case_arg_aliases(op, existing)
    # Auto case-fix must NOT be emitted because `from: MarketplaceIds` is claimed
    by_from = {a["from"] for a in result}
    assert by_from == {"MarketplaceIds"}
    # Hand-authored entry preserved
    assert {"from": "MarketplaceIds", "to": "somethingCustom"} in result


def test_same_from_with_wrap_field_blocks_auto_emission(build_script):
    """Existing rule with ``wrap: list`` (e.g. ``MarketplaceIds → marketplaceIds, wrap: list``)
    must block the case-fix-only auto emission for the same ``from``.
    The overlay's wrap semantics are stronger than the auto case fix."""
    op = {"parameters": [{"name": "marketplaceIds", "in": "query"}]}
    existing = [{"from": "MarketplaceIds", "to": "marketplaceIds", "wrap": "list"}]
    result = build_script.derive_pascal_case_arg_aliases(op, existing)
    matching = [a for a in result if a.get("from") == "MarketplaceIds"]
    assert len(matching) == 1
    assert matching[0].get("wrap") == "list"


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_no_parameters_no_body_returns_existing_unchanged(build_script):
    existing = [{"from": "X", "to": "y"}]
    result = build_script.derive_pascal_case_arg_aliases({}, list(existing))
    assert result == existing


def test_param_without_name_is_skipped(build_script):
    op = {"parameters": [{"in": "query"}, {"name": "valid", "in": "query"}]}
    result = build_script.derive_pascal_case_arg_aliases(op, [])
    pairs = {(a["from"], a["to"]) for a in result}
    assert pairs == {("Valid", "valid")}


def test_empty_string_name_is_skipped(build_script):
    op = {"parameters": [{"name": "", "in": "query"}]}
    result = build_script.derive_pascal_case_arg_aliases(op, [])
    assert result == []


def test_query_and_body_aliases_combine(build_script):
    op = {
        "parameters": [
            {"name": "limit", "in": "query"},
        ],
        "requestBody": {
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "campaignName": {"type": "string"},
                        },
                    }
                }
            }
        },
    }
    result = build_script.derive_pascal_case_arg_aliases(op, [])
    pairs = {(a["from"], a["to"]) for a in result}
    assert ("Limit", "limit") in pairs
    assert ("CampaignName", "campaignName") in pairs
