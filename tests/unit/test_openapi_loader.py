"""Tests for the bundled OpenAPI spec loader helper.

Covers ``load_bundled_spec(name)`` which is used by downstream features
(e.g. the async-hint schema-validation test and the CreateReport filter
guardrail) to read a single bundled spec by resource name without having
to know the repo-vs-wheel file layout.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


def test_load_bundled_spec_returns_dict_with_components():
    from amazon_ads_mcp.utils.openapi.loader import load_bundled_spec

    spec = load_bundled_spec("AdsAPIv1All")
    assert isinstance(spec, dict)
    assert "components" in spec
    assert "schemas" in spec["components"]
    # AdProduct is the enum we rely on for the CreateReport filter guardrail.
    assert "AdProduct" in spec["components"]["schemas"]
    assert spec["components"]["schemas"]["AdProduct"].get("enum")


def test_load_bundled_spec_exported_from_package():
    # Public re-export so callers can ``from amazon_ads_mcp.utils.openapi import ...``.
    from amazon_ads_mcp.utils.openapi import load_bundled_spec

    spec = load_bundled_spec("AdsAPIv1All")
    assert "paths" in spec


def test_load_bundled_spec_raises_on_unknown_name():
    from amazon_ads_mcp.utils.openapi.loader import load_bundled_spec

    with pytest.raises(FileNotFoundError):
        load_bundled_spec("NopeThisIsNotASpec")


def test_load_bundled_spec_rejects_path_traversal():
    """Name must resolve within the resources dir — no ``..`` escape."""
    from amazon_ads_mcp.utils.openapi.loader import load_bundled_spec

    with pytest.raises((FileNotFoundError, ValueError)):
        load_bundled_spec("../../../etc/passwd")


def test_load_bundled_spec_reads_from_dist_when_present(tmp_path: Path, monkeypatch):
    """When ``dist/openapi/resources/{name}.json`` exists relative to CWD, prefer it.

    Mirrors the resolution order used by ``ServerBuilder._mount_resource_servers``.
    """
    from amazon_ads_mcp.utils.openapi import loader as loader_mod

    # Synthesize a fake repo layout under tmp_path.
    dist_dir = tmp_path / "dist" / "openapi" / "resources"
    dist_dir.mkdir(parents=True)
    (dist_dir / "FakeSpec.json").write_text(
        json.dumps({"openapi": "3.0.1", "components": {"schemas": {}}, "paths": {}})
    )

    monkeypatch.chdir(tmp_path)
    # Clear any module-level cache so the new CWD is used.
    cache_reset = getattr(loader_mod, "_bundled_spec_cache", None)
    if isinstance(cache_reset, dict):
        cache_reset.clear()

    spec = loader_mod.load_bundled_spec("FakeSpec")
    assert spec["openapi"] == "3.0.1"


def test_load_bundled_spec_caches_result():
    """Repeated calls for the same name return the same object (no re-read)."""
    from amazon_ads_mcp.utils.openapi.loader import load_bundled_spec

    first = load_bundled_spec("AdsAPIv1All")
    second = load_bundled_spec("AdsAPIv1All")
    assert first is second
