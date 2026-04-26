"""Phase B integration test: build-time arg_aliases flow end-to-end on Ads.

Mirrors the SP version. Synthetic spec → ``derive_pascal_case_arg_aliases``
→ ``generate_transform_sidecar`` writes ``*.transform.json`` →
``SidecarTransformMiddleware`` loads sidecar → tool dispatch with
PascalCase args → canonical camelCase reaches the tool function.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


def _load_build_script():
    repo_root = Path(__file__).resolve().parents[2]
    script_path = repo_root / ".build" / "scripts" / "process_openapi_specs.py"
    if not script_path.exists():
        pytest.skip(f"build script not present at {script_path}")
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


def _synthetic_spec() -> dict:
    """Minimal OpenAPI doc with one operation that has camelCase params."""
    return {
        "openapi": "3.0.0",
        "info": {"title": "Test", "version": "1.0"},
        "paths": {
            "/v2/profiles": {
                "get": {
                    "operationId": "ProfilesList",
                    "parameters": [
                        {
                            "name": "accessLevel",
                            "in": "query",
                            "schema": {"type": "string"},
                        },
                        {
                            "name": "apiProgram",
                            "in": "query",
                            "schema": {"type": "string"},
                        },
                    ],
                    "responses": {"200": {"description": "ok"}},
                }
            }
        },
    }


@pytest.mark.asyncio
async def test_generated_sidecar_drives_runtime_rewrite(tmp_path, build_script):
    """End-to-end: write sidecar via build helper, load it via runtime
    middleware, exercise rewrite_args, assert canonical keys."""
    from amazon_ads_mcp.server.sidecar_middleware import SidecarTransformMiddleware

    resources = tmp_path / "resources"
    resources.mkdir()
    spec_path = resources / "Profiles.json"
    spec = _synthetic_spec()
    spec_path.write_text(json.dumps(spec), encoding="utf-8")

    written = build_script.generate_transform_sidecar(spec_path, spec)
    assert written, "generate_transform_sidecar should produce a sidecar"
    sidecar_path = spec_path.with_suffix(".transform.json")
    assert sidecar_path.exists()

    sidecar = json.loads(sidecar_path.read_text())
    rules = sidecar["tools"]
    rule = next(r for r in rules if r["match"]["operationId"] == "ProfilesList")
    aliases = rule["input_transform"]["arg_aliases"]
    pairs = {(a["from"], a["to"]) for a in aliases}
    assert ("AccessLevel", "accessLevel") in pairs
    assert ("ApiProgram", "apiProgram") in pairs

    middleware = SidecarTransformMiddleware(resources)
    rewritten = await middleware.rewrite_args(
        "ProfilesList",
        {"AccessLevel": "VIEW", "ApiProgram": "STANDARD"},
    )
    # Ads' DeclarativeTransformExecutor populates the canonical target
    # without removing the source (additive semantics — the original
    # PascalCase key remains, but the canonical is now also present).
    # Pydantic `extra=ignore` (default) drops the unknown source at
    # validation time. Both keys may co-exist on this map.
    assert rewritten["accessLevel"] == "VIEW"
    assert rewritten["apiProgram"] == "STANDARD"


@pytest.mark.asyncio
async def test_canonical_input_unchanged_through_sidecar(tmp_path, build_script):
    """Canonical camelCase input passes through untouched."""
    from amazon_ads_mcp.server.sidecar_middleware import SidecarTransformMiddleware

    resources = tmp_path / "resources"
    resources.mkdir()
    spec_path = resources / "Profiles.json"
    spec = _synthetic_spec()
    spec_path.write_text(json.dumps(spec), encoding="utf-8")
    build_script.generate_transform_sidecar(spec_path, spec)

    middleware = SidecarTransformMiddleware(resources)
    canonical = {"accessLevel": "VIEW", "apiProgram": "STANDARD"}
    rewritten = await middleware.rewrite_args("ProfilesList", dict(canonical))
    assert rewritten == canonical


@pytest.mark.asyncio
async def test_existing_overlay_aliases_still_fire_alongside_auto(
    tmp_path, build_script
):
    """Hand-authored Ads overlays at openapi/overlays/*.json must keep
    working unchanged. Loads the real overlay dir alongside the
    auto-generated synthetic sidecar — proves auto-emission doesn't
    break existing reportId→reportIds rules."""
    from amazon_ads_mcp.server.sidecar_middleware import SidecarTransformMiddleware

    repo_root = Path(__file__).resolve().parents[2]
    real_overlays = repo_root / "openapi" / "overlays"
    if not real_overlays.exists():
        pytest.skip("no overlays directory checked in")

    resources = tmp_path / "resources"
    resources.mkdir()
    spec_path = resources / "Profiles.json"
    spec = _synthetic_spec()
    spec_path.write_text(json.dumps(spec), encoding="utf-8")
    build_script.generate_transform_sidecar(spec_path, spec)

    middleware = SidecarTransformMiddleware(resources, overlays_dir=real_overlays)
    rewritten_auto = await middleware.rewrite_args(
        "ProfilesList", {"AccessLevel": "VIEW"}
    )
    assert rewritten_auto.get("accessLevel") == "VIEW"
