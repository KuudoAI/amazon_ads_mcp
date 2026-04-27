"""Coverage-pushing tests for ``utils.openapi.loader.OpenAPISpecLoader``.

Round-13 coverage report had this module at 14% (88 of 102 statements
uncovered). The class loads, merges, and persists OpenAPI specs from a
manifest file. Tests use ``tmp_path`` to avoid touching real spec files.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from amazon_ads_mcp.utils.openapi.loader import OpenAPISpecLoader


# --- Fixtures -------------------------------------------------------------


@pytest.fixture
def spec_root(tmp_path: Path) -> Path:
    """Build a minimal spec tree with manifest + two specs.

    Layout:
        tmp_path/
            openapi/
                manifest.json     (mirrors loader's expected shape)
                campaigns.json    (a tiny OpenAPI-shaped doc)
                profiles.json
    """
    root = tmp_path / "openapi"
    root.mkdir()

    campaigns_spec = {
        "openapi": "3.0.0",
        "info": {"title": "Campaigns", "version": "1.0"},
        "paths": {
            "/campaigns": {
                "get": {
                    "operationId": "listCampaigns",
                    "parameters": [
                        # auth headers — should be stripped by merge
                        {"in": "header", "name": "Authorization"},
                        {"in": "header", "name": "Amazon-Advertising-API-ClientId"},
                        # non-auth header — should be preserved
                        {"in": "header", "name": "X-Custom"},
                        # query parameter — should be preserved
                        {"in": "query", "name": "stateFilter"},
                    ],
                    "responses": {"200": {"description": "ok"}},
                }
            }
        },
        "components": {
            "schemas": {"Campaign": {"type": "object"}},
        },
    }

    profiles_spec = {
        "openapi": "3.0.0",
        "info": {"title": "Profiles", "version": "1.0"},
        "paths": {
            "/profiles": {
                "get": {"responses": {"200": {"description": "ok"}}}
            }
        },
        "components": {
            "schemas": {"Profile": {"type": "object"}},
        },
    }

    (root / "campaigns.json").write_text(json.dumps(campaigns_spec))
    (root / "profiles.json").write_text(json.dumps(profiles_spec))

    manifest = {
        "successful": 2,
        "specs": [
            {
                "status": "success",
                "file": "campaigns.json",
                "category": "advertising",
                "resource": "campaigns",
            },
            {
                "status": "success",
                "file": "profiles.json",
                "category": "advertising",
                "resource": "profiles",
            },
        ],
    }
    # The loader stores paths "relative to openapi/", and prepends
    # base_path.parent. So with base_path=tmp_path/openapi/amazon_ads_apis,
    # parent=tmp_path/openapi, and a manifest entry "campaigns.json" must
    # resolve to tmp_path/openapi/campaigns.json. Match that layout:
    api_dir = root / "amazon_ads_apis"
    api_dir.mkdir()
    (api_dir / "manifest.json").write_text(json.dumps(manifest))

    return api_dir  # base_path the loader expects


@pytest.fixture
def loader_with_specs(spec_root: Path) -> OpenAPISpecLoader:
    loader = OpenAPISpecLoader(base_path=spec_root)
    loader.load_all_specs()
    return loader


# --- load_all_specs -------------------------------------------------------


class TestLoadAllSpecs:
    def test_loads_specs_listed_in_manifest(self, spec_root: Path) -> None:
        loader = OpenAPISpecLoader(base_path=spec_root)
        specs = loader.load_all_specs()
        assert len(specs) == 2
        assert "advertising/campaigns" in specs
        assert "advertising/profiles" in specs

    def test_failed_spec_status_is_skipped(self, spec_root: Path) -> None:
        # Add a "failed"-status entry; loader should skip it.
        manifest_path = spec_root / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["specs"].append({
            "status": "failed",
            "file": "broken.json",
            "category": "x",
            "resource": "y",
        })
        manifest_path.write_text(json.dumps(manifest))

        loader = OpenAPISpecLoader(base_path=spec_root)
        loader.load_all_specs()
        assert "x/y" not in loader.specs

    def test_missing_spec_file_logged_not_raised(
        self, spec_root: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """If a manifest references a file that doesn't exist, the loader
        skips it silently (no spec gets added). Logged at DEBUG level."""
        manifest_path = spec_root / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["specs"].append({
            "status": "success",
            "file": "does_not_exist.json",
            "category": "ghost",
            "resource": "town",
        })
        manifest_path.write_text(json.dumps(manifest))

        loader = OpenAPISpecLoader(base_path=spec_root)
        loader.load_all_specs()
        # Missing-file path: spec_path.exists() returns False → no entry added.
        assert "ghost/town" not in loader.specs

    def test_missing_manifest_falls_back_to_legacy(self, tmp_path: Path) -> None:
        """No manifest → loader calls _load_legacy_specs.

        Since legacy paths are absolute file paths in the working dir,
        and they don't exist in tmp_path, the result is empty — but the
        function must not raise."""
        empty_dir = tmp_path / "no_manifest"
        empty_dir.mkdir()
        loader = OpenAPISpecLoader(base_path=empty_dir)
        result = loader.load_all_specs()
        # Empty result; the legacy spec files don't exist in this test env.
        assert isinstance(result, dict)


# --- merge_specs ----------------------------------------------------------


class TestMergeSpecs:
    def test_merged_has_paths_from_all_specs(
        self, loader_with_specs: OpenAPISpecLoader
    ) -> None:
        merged = loader_with_specs.merge_specs()
        assert "/campaigns" in merged["paths"]
        assert "/profiles" in merged["paths"]

    def test_merged_components_combined(
        self, loader_with_specs: OpenAPISpecLoader
    ) -> None:
        merged = loader_with_specs.merge_specs()
        assert "Campaign" in merged["components"]["schemas"]
        assert "Profile" in merged["components"]["schemas"]

    def test_merged_includes_all_three_regional_servers(
        self, loader_with_specs: OpenAPISpecLoader
    ) -> None:
        merged = loader_with_specs.merge_specs()
        urls = {s["url"] for s in merged["servers"]}
        assert urls == {
            "https://advertising-api.amazon.com",
            "https://advertising-api-eu.amazon.com",
            "https://advertising-api-fe.amazon.com",
        }

    def test_merged_includes_bearer_security_scheme(
        self, loader_with_specs: OpenAPISpecLoader
    ) -> None:
        merged = loader_with_specs.merge_specs()
        schemes = merged["components"]["securitySchemes"]
        assert schemes["bearerAuth"]["scheme"] == "bearer"

    def test_merge_caches_result(
        self, loader_with_specs: OpenAPISpecLoader
    ) -> None:
        first = loader_with_specs.merge_specs()
        second = loader_with_specs.merge_specs()
        assert first is second  # cached identity, not just equality

    def test_auth_headers_stripped_from_merged_paths(
        self, loader_with_specs: OpenAPISpecLoader
    ) -> None:
        merged = loader_with_specs.merge_specs()
        params = merged["paths"]["/campaigns"]["get"]["parameters"]
        names = {p["name"] for p in params}
        assert "Authorization" not in names
        assert "Amazon-Advertising-API-ClientId" not in names
        # Non-auth header preserved
        assert "X-Custom" in names
        # Query param preserved
        assert "stateFilter" in names


# --- get_categories -------------------------------------------------------


class TestGetCategories:
    def test_groups_resources_by_category(
        self, loader_with_specs: OpenAPISpecLoader
    ) -> None:
        cats = loader_with_specs.get_categories()
        assert "advertising" in cats
        assert sorted(cats["advertising"]) == ["campaigns", "profiles"]

    def test_unknown_category_falls_back(self, tmp_path: Path) -> None:
        """Specs with no 'category' key in info bucket under 'unknown'."""
        loader = OpenAPISpecLoader(base_path=tmp_path)
        loader.specs["x/y"] = {"spec": {}, "info": {"resource": "y"}}
        cats = loader.get_categories()
        assert "unknown" in cats
        assert "y" in cats["unknown"]


# --- save_merged_spec / load_and_merge_specs ------------------------------


class TestSaveAndLoadMerge:
    def test_save_writes_valid_json(
        self, loader_with_specs: OpenAPISpecLoader, tmp_path: Path
    ) -> None:
        out_path = tmp_path / "merged.json"
        loader_with_specs.save_merged_spec(out_path)
        assert out_path.exists()
        # Round-trip the JSON to validate it
        data = json.loads(out_path.read_text())
        assert data["info"]["title"] == "Amazon Ads API - Complete"

    def test_load_and_merge_returns_merged_spec(
        self, spec_root: Path
    ) -> None:
        loader = OpenAPISpecLoader(base_path=spec_root)
        merged = loader.load_and_merge_specs()
        assert "/campaigns" in merged["paths"]
        assert "Campaign" in merged["components"]["schemas"]
