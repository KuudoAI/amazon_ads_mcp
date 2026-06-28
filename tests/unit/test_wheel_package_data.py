"""Wheel-content test: assert the packaged JSON resources ship in the wheel.

Marked @pytest.mark.slow because it shells out to a wheel build.
Local dev: `uv run pytest -m "not slow"` skips this.
CI: `uv run pytest -m slow` runs it.

Two failure classes this catches that source-tree tests cannot:

1. Packaging-backend misconfiguration (a [[tool.poetry.include]] entry with
   the wrong path or format) — the adsv1 catalog assertions.
2. Packaging *drift* — the OpenAPI specs + packages.json regressing out of
   the wheel, which left pip installs with zero API tools (issue #91). These
   resources are staged from dist/openapi/ into the package tree at build
   time, so the test stages first, then builds the wheel from source.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
STAGER = REPO_ROOT / "src" / "amazon_ads_mcp" / "build" / "stage_wheel_resources.py"

# Committed catalog/contract files (shipped regardless of staging).
REQUIRED_CATALOG_IN_WHEEL = [
    "amazon_ads_mcp/resources/adsv1/dimensions.json",
    "amazon_ads_mcp/resources/adsv1/metrics.json",
    "amazon_ads_mcp/resources/adsv1/index.json",
    "amazon_ads_mcp/resources/adsv1/catalog_meta.json",
    "amazon_ads_mcp/resources/adsv1/dimension_label_index.json",
    "amazon_ads_mcp/resources/contract/jsonschema_error_codes.json",
]

# Staged OpenAPI resources that MUST ship so pip installs register API tools.
# These are the file stems behind the package aliases in the issue #91 repro
# (profiles, reporting-version-3, ads-api-v1-sp, ads-api-v1-sb) plus the
# namespace map the loader and middleware both consume.
REQUIRED_SPECS_IN_WHEEL = [
    "amazon_ads_mcp/resources/packages.json",
    "amazon_ads_mcp/resources/AccountsProfiles.json",
    "amazon_ads_mcp/resources/ReportingVersion3.json",
    "amazon_ads_mcp/resources/AdsAPIv1SponsoredProducts.json",
    "amazon_ads_mcp/resources/AdsAPIv1SponsoredBrands.json",
]

# A wheel that registers tools must carry a healthy spec catalog, not just a
# couple of files. The dist tree has ~55 bare specs; require a clear majority
# so a partial-staging regression still trips the gate.
MIN_TOP_LEVEL_SPECS = 40


def _run_stager(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(STAGER), *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )


def _build_wheel(outdir: Path) -> subprocess.CompletedProcess:
    """Build a wheel from source using whichever builder is available.

    MUST build the wheel directly from the source tree (`--wheel`), not the
    default sdist->wheel path: the staged resources are gitignored, and
    poetry-core's sdist step honours .gitignore, so a wheel built from the
    sdist would drop them. A source-tree wheel build picks them up via the
    [[tool.poetry.include]] globs.
    """
    if shutil.which("uv"):
        return subprocess.run(
            ["uv", "build", "--wheel", "--out-dir", str(outdir)],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )
    return subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "--outdir", str(outdir)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )


@pytest.fixture(scope="module")
def wheel_names() -> set[str]:
    """Stage resources, build a wheel from source, return its namelist.

    Cleans the staged (gitignored) files afterwards so the working tree is
    left as found — they are pure build artifacts, regenerable from dist/.
    """
    import tempfile

    stage = _run_stager()
    if stage.returncode != 0:
        pytest.fail(
            f"staging failed:\nstdout:\n{stage.stdout}\nstderr:\n{stage.stderr}"
        )
    try:
        with tempfile.TemporaryDirectory() as td:
            outdir = Path(td)
            result = _build_wheel(outdir)
            if result.returncode != 0:
                pytest.fail(
                    "wheel build failed:\n"
                    f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
                )
            wheels = list(outdir.glob("*.whl"))
            assert len(wheels) == 1, f"expected one wheel, got {wheels}"
            with zipfile.ZipFile(wheels[0]) as zf:
                return set(zf.namelist())
    finally:
        _run_stager("--clean")


@pytest.mark.slow
def test_built_wheel_contains_catalog_files(wheel_names: set[str]):
    """Committed adsv1 catalog + contract files ship in the wheel."""
    missing = [p for p in REQUIRED_CATALOG_IN_WHEEL if p not in wheel_names]
    assert not missing, (
        f"wheel is missing packaged catalog files: {missing}\n"
        "wheel contents:\n" + "\n".join(sorted(wheel_names))
    )


@pytest.mark.slow
def test_built_wheel_contains_openapi_specs(wheel_names: set[str]):
    """Staged OpenAPI specs + packages.json ship (issue #91 regression gate).

    Without these, a pip install mounts zero API specs and exposes only the
    builtin tools — the exact failure reported in issue #91.
    """
    missing = [p for p in REQUIRED_SPECS_IN_WHEEL if p not in wheel_names]
    assert not missing, (
        "wheel is missing staged OpenAPI specs (pip installs would register "
        f"0 API tools — issue #91): {missing}\n"
        "Did `stage_wheel_resources` run before the build, and was the wheel "
        "built from source (not sdist->wheel)?"
    )


@pytest.mark.slow
def test_built_wheel_ships_full_spec_catalog(wheel_names: set[str]):
    """A healthy majority of the dist spec catalog ships, not a token few."""
    top_level_specs = [
        n
        for n in wheel_names
        if n.startswith("amazon_ads_mcp/resources/")
        and n.count("/") == 2  # resources/<file>.json, not a subdir
        and n.endswith(".json")
        and not n.endswith((".media.json", ".manifest.json", ".transform.json"))
        and not n.endswith("packages.json")
    ]
    assert len(top_level_specs) >= MIN_TOP_LEVEL_SPECS, (
        f"only {len(top_level_specs)} top-level OpenAPI specs in wheel "
        f"(expected >= {MIN_TOP_LEVEL_SPECS}); staging may be partial.\n"
        + "\n".join(sorted(top_level_specs))
    )
