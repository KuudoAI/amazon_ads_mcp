"""Dynamic OpenAPI specification loader for Amazon Ads MCP server.

This module provides functionality for loading, merging, and managing
OpenAPI specifications for the Amazon Ads API, enabling dynamic
API integration.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


# Module-level cache for load_bundled_spec — one parse per spec name per process.
_bundled_spec_cache: Dict[str, Dict[str, Any]] = {}


def _bundled_spec_search_paths() -> List[Path]:
    """Candidate directories for a named bundled spec, in preference order.

    Mirrors the three-tier fallback used by
    :class:`amazon_ads_mcp.server.server_builder.ServerBuilder`:

    1. ``dist/openapi/resources/`` — minified production build output (CWD-relative).
    2. ``openapi/resources/`` — raw dev-tree source (CWD-relative).
    3. ``<pkg>/resources/`` — wheel-packaged fallback relative to this module.
    """
    return [
        Path("dist") / "openapi" / "resources",
        Path("openapi") / "resources",
        Path(__file__).resolve().parent.parent.parent / "resources",
    ]


def load_bundled_spec(name: str) -> Dict[str, Any]:
    """Load a single bundled OpenAPI spec by resource name (no extension).

    Used by features that need direct access to the raw spec — e.g. the
    CreateReport filter guardrail (reads ``components.schemas.AdProduct.enum``)
    and the async-hint schema-validation test (validates the hint's request
    example against ``components.schemas.CreateReportRequest``).

    :param name: Base name of the spec, e.g. ``"AdsAPIv1All"``. No path
        traversal allowed.
    :raises ValueError: If *name* contains path separators or traversal markers.
    :raises FileNotFoundError: If the spec cannot be found under any known
        search path.
    :return: Parsed spec dict. Cached per-process after the first call; repeat
        calls return the same object.
    """
    # Reject path traversal outright — name must be a bare identifier.
    if "/" in name or "\\" in name or ".." in name:
        raise ValueError(
            f"load_bundled_spec: invalid name {name!r} (no path separators allowed)"
        )

    cached = _bundled_spec_cache.get(name)
    if cached is not None:
        return cached

    filename = f"{name}.json"
    tried: List[Path] = []
    for base in _bundled_spec_search_paths():
        candidate = base / filename
        tried.append(candidate)
        if candidate.exists():
            with open(candidate) as fh:
                spec = json.load(fh)
            _bundled_spec_cache[name] = spec
            return spec

    raise FileNotFoundError(
        f"load_bundled_spec: could not locate {filename!r}; "
        f"tried: {[str(p) for p in tried]}"
    )


class OpenAPISpecLoader:
    """Load and merge OpenAPI specifications dynamically.

    Handles loading of multiple OpenAPI specifications from a manifest
    file and merging them into a single comprehensive specification
    for the Amazon Ads API.

    :param base_path: Base path for OpenAPI specifications
    :type base_path: Path
    :param manifest_path: Path to the manifest file
    :type manifest_path: Path
    :param specs: Dictionary of loaded specifications
    :type specs: Dict[str, Any]
    :param merged_spec: Cached merged specification
    :type merged_spec: Optional[Dict[str, Any]]
    """

    def __init__(self, base_path: Path = Path("openapi/amazon_ads_apis")):
        self.base_path = base_path
        self.manifest_path = base_path / "manifest.json"
        self.specs = {}
        self.merged_spec = None

    def load_all_specs(self) -> Dict[str, Any]:
        """Load all OpenAPI specifications from the manifest.

        Loads all OpenAPI specifications listed in the manifest file.
        Falls back to legacy specifications if manifest is not found.

        :return: Dictionary of loaded specifications
        :rtype: Dict[str, Any]
        """
        if not self.manifest_path.exists():
            logger.warning(f"Manifest not found at {self.manifest_path}")
            return self._load_legacy_specs()

        with open(self.manifest_path) as f:
            manifest = json.load(f)

        logger.info(f"Loading {manifest['successful']} OpenAPI specifications")

        # Load each successful spec
        for spec_info in manifest["specs"]:
            if spec_info["status"] == "success":
                # Fix path - the manifest stores paths relative to openapi/
                spec_path = self.base_path.parent / spec_info["file"]
                if spec_path.exists():
                    try:
                        with open(spec_path) as f:
                            spec = json.load(f)

                        category = spec_info["category"]
                        resource = spec_info["resource"]
                        key = f"{category}/{resource}"

                        self.specs[key] = {"spec": spec, "info": spec_info}
                        logger.debug(f"Loaded {key}")
                    except Exception as e:
                        logger.error(f"Failed to load {spec_path}: {e}")

        logger.info(f"Successfully loaded {len(self.specs)} specifications")
        return self.specs

    def _load_legacy_specs(self) -> Dict[str, Any]:
        """Load legacy manually downloaded specs as fallback.

        Loads legacy OpenAPI specifications as a fallback when
        the manifest file is not available.

        :return: Dictionary of loaded legacy specifications
        :rtype: Dict[str, Any]
        """
        legacy_specs = {
            "test_accounts": "openapi/test_account.json",
            "profiles": "openapi/profiles.json",
            "exports": "openapi/exports.json",
            "ads_api": "openapi/amazon_ads_all.json",
        }

        for name, path in legacy_specs.items():
            spec_path = Path(path)
            if spec_path.exists():
                try:
                    with open(spec_path) as f:
                        spec = json.load(f)
                    self.specs[name] = {
                        "spec": spec,
                        "info": {"resource": name, "category": "legacy"},
                    }
                    logger.info(f"Loaded legacy spec: {name}")
                except Exception as e:
                    logger.error(f"Failed to load legacy spec {path}: {e}")

        return self.specs

    def merge_specs(self) -> Dict[str, Any]:
        """Merge all loaded specs into a single OpenAPI specification.

        Combines all loaded OpenAPI specifications into a single
        comprehensive specification for the Amazon Ads API.

        :return: Merged OpenAPI specification
        :rtype: Dict[str, Any]
        """
        if self.merged_spec:
            return self.merged_spec

        # Base structure
        merged = {
            "openapi": "3.0.1",
            "info": {
                "title": "Amazon Ads API - Complete",
                "version": "1.0",
                "description": "Comprehensive Amazon Ads API including all services",
            },
            "servers": [
                {
                    "url": "https://advertising-api.amazon.com",
                    "description": "North America",
                },
                {
                    "url": "https://advertising-api-eu.amazon.com",
                    "description": "Europe",
                },
                {
                    "url": "https://advertising-api-fe.amazon.com",
                    "description": "Far East",
                },
            ],
            "paths": {},
            "components": {
                "schemas": {},
                "securitySchemes": {
                    "bearerAuth": {
                        "type": "http",
                        "scheme": "bearer",
                    }
                },
                "parameters": {},
                "responses": {},
            },
        }

        # Merge paths and components from each spec
        for key, spec_data in self.specs.items():
            spec = spec_data["spec"]

            # Merge paths
            if "paths" in spec:
                for path, path_item in spec["paths"].items():
                    # Process each path item to remove auth headers
                    processed_path_item = self._remove_auth_headers(path_item)

                    if path not in merged["paths"]:
                        merged["paths"][path] = processed_path_item
                    else:
                        # Merge operations if path already exists
                        for method, operation in processed_path_item.items():
                            if method not in merged["paths"][path]:
                                merged["paths"][path][method] = operation

            # Merge components
            if "components" in spec:
                for component_type in [
                    "schemas",
                    "parameters",
                    "responses",
                    "examples",
                    "requestBodies",
                    "headers",
                ]:
                    if component_type in spec["components"]:
                        if component_type not in merged["components"]:
                            merged["components"][component_type] = {}

                        # Add prefix to avoid conflicts
                        prefix = key.replace("/", "_").replace(" ", "_")
                        for name, component in spec["components"][
                            component_type
                        ].items():
                            # Use original name if no conflict, otherwise prefix it
                            final_name = name
                            if name in merged["components"][component_type]:
                                final_name = f"{prefix}_{name}"
                            merged["components"][component_type][
                                final_name
                            ] = component

        self.merged_spec = merged
        logger.info(
            f"Merged {len(merged['paths'])} paths from {len(self.specs)} specifications"
        )

        return merged

    def get_categories(self) -> Dict[str, List[str]]:
        """Get all categories and their resources."""
        categories = {}
        for key, spec_data in self.specs.items():
            info = spec_data["info"]
            category = info.get("category", "unknown")
            resource = info.get("resource", key)

            if category not in categories:
                categories[category] = []
            categories[category].append(resource)

        return categories

    def _remove_auth_headers(
        self, path_item: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Remove authentication headers from path item parameters."""
        auth_headers = {
            "Amazon-Advertising-API-ClientId",
            "Amazon-Advertising-API-Scope",
            "Authorization",
        }

        processed = {}
        for method, operation in path_item.items():
            if method in ["get", "post", "put", "delete", "patch"]:
                processed[method] = operation.copy()

                # Remove auth headers from parameters
                if "parameters" in operation:
                    processed[method]["parameters"] = [
                        param
                        for param in operation["parameters"]
                        if not (
                            param.get("in") == "header"
                            and param.get("name") in auth_headers
                        )
                    ]

        return processed

    def save_merged_spec(self, output_path: Path):
        """Save the merged specification to a file."""
        merged = self.merge_specs()
        with open(output_path, "w") as f:
            json.dump(merged, f, indent=2)
        logger.info(f"Saved merged spec to {output_path}")

    def load_and_merge_specs(self) -> Dict[str, Any]:
        """Load all specs and return the merged specification."""
        self.load_all_specs()
        return self.merge_specs()
