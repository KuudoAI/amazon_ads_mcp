"""Wheel-content test: assert the packaged JSON resources ship in the wheel.

Marked @pytest.mark.slow because it shells out to a wheel build.
Local dev: `uv run pytest -m "not slow"` skips this.
CI: `uv run pytest -m slow` runs it.

Failure classes this catches that source-tree tests cannot:

1. Packaging-backend misconfiguration (a [[tool.poetry.include]] entry with
   the wrong path or format) — the adsv1 catalog assertions.
2. Packaging *drift* — the OpenAPI specs + packages.json regressing out of
   the wheel, which left pip installs with zero API tools (issue #91). The
   build_package.py PEP 517 shim stages these from dist/openapi/ on every
   wheel build, so the test builds without any pre-staging step — exactly
   what a `pip install .` does.
3. Wheel purity — a [tool.poetry.build] script would platform-tag the wheel;
   the tag assertion pins py3-none-any.
4. Sdist self-sufficiency — the sdist must carry dist/openapi + the stager
   so sdist->wheel rebuilds (pip --no-binary, distro packaging) stage too.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tarfile
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

# Arg-alias overlays the SidecarTransformMiddleware consumes at runtime.
# Aliases live exclusively in overlays, so a wheel without them silently
# regresses aliased tool calls to the Amazon 400 loop they exist to close.
REQUIRED_OVERLAYS_IN_WHEEL = [
    "amazon_ads_mcp/resources/overlays/AdsAPIv1All.json",
    "amazon_ads_mcp/resources/overlays/AdsAPIv1Beta.json",
]

# A wheel that registers tools must carry the full spec catalog. The dist
# tree has ~55 bare specs; require a clear majority so a partial-staging
# regression still trips the gate.
MIN_TOP_LEVEL_SPECS = 40

# Sdist contents that make sdist->wheel rebuilds self-sufficient: the
# canonical staging sources, the stager, and the PEP 517 backend shim.
REQUIRED_IN_SDIST = [
    "dist/openapi/resources/packages.json",
    "dist/openapi/resources/AccountsProfiles.json",
    "dist/openapi/overlays/AdsAPIv1All.json",
    "src/amazon_ads_mcp/build/stage_wheel_resources.py",
    "build_package.py",
]


def _run_stager(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(STAGER), *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )


def _build(kind: str, outdir: Path) -> subprocess.CompletedProcess:
    """Build a wheel or sdist using whichever builder is available.

    No pre-staging: the build_package.py PEP 517 shim stages dist/openapi
    resources inside the build, the same way every consumer build path does.
    """
    if shutil.which("uv"):
        return subprocess.run(
            ["uv", "build", f"--{kind}", "--out-dir", str(outdir)],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )
    return subprocess.run(
        [sys.executable, "-m", "build", f"--{kind}", "--outdir", str(outdir)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )


@pytest.fixture(scope="module")
def wheel_path(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Build a wheel with no pre-staging and return its path.

    Cleans the staged (gitignored) files afterwards so the working tree is
    left as found — they are pure build artifacts, regenerable from dist/.
    """
    outdir = tmp_path_factory.mktemp("wheel")
    try:
        result = _build("wheel", outdir)
        if result.returncode != 0:
            pytest.fail(
                "wheel build failed:\n"
                f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
            )
        wheels = list(outdir.glob("*.whl"))
        assert len(wheels) == 1, f"expected one wheel, got {wheels}"
        return wheels[0]
    finally:
        _run_stager("--clean")


@pytest.fixture(scope="module")
def wheel_names(wheel_path: Path) -> set[str]:
    with zipfile.ZipFile(wheel_path) as zf:
        return set(zf.namelist())


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
        "Is the build_package.py PEP 517 shim wired as the build backend?"
    )


@pytest.mark.slow
def test_built_wheel_contains_overlays(wheel_names: set[str]):
    """Arg-alias overlays ship so aliased tool calls keep working."""
    missing = [p for p in REQUIRED_OVERLAYS_IN_WHEEL if p not in wheel_names]
    assert not missing, (
        f"wheel is missing arg-alias overlays: {missing}\n"
        "SidecarTransformMiddleware aliases live exclusively in overlays."
    )


@pytest.mark.slow
def test_built_wheel_ships_full_spec_catalog(wheel_names: set[str]):
    """The wheel carries the full dist spec catalog."""
    top_level_specs = [
        n
        for n in wheel_names
        if n.startswith("amazon_ads_mcp/resources/")
        and n.count("/") == 2  # resources/<file>.json only, no subdirs
        and n.endswith(".json")
        and not n.endswith((".media.json", ".manifest.json", ".transform.json"))
        and not n.endswith("packages.json")
    ]
    assert len(top_level_specs) >= MIN_TOP_LEVEL_SPECS, (
        f"only {len(top_level_specs)} top-level OpenAPI specs in wheel "
        f"(expected >= {MIN_TOP_LEVEL_SPECS}); staging may be partial.\n"
        + "\n".join(sorted(top_level_specs))
    )


@pytest.mark.slow
def test_built_wheel_is_pure(wheel_path: Path):
    """The wheel must stay py3-none-any.

    A [tool.poetry.build] script (an earlier candidate for build-time
    staging) makes poetry-core emit a platform-tagged wheel, which would
    break installs on every other platform/interpreter.
    """
    assert wheel_path.name.endswith("-py3-none-any.whl"), (
        f"wheel is not pure: {wheel_path.name} — did build-time staging "
        "move into a [tool.poetry.build] script?"
    )


@pytest.mark.slow
def test_sdist_is_self_sufficient(tmp_path_factory: pytest.TempPathFactory):
    """The sdist carries dist/openapi + stager + backend shim.

    A wheel rebuilt from the sdist (pip --no-binary, distro packaging) must
    stage the same resources; before this guard, the published sdist shipped
    zero OpenAPI specs and could not re-stage (issue #91's second act).
    """
    outdir = tmp_path_factory.mktemp("sdist")
    result = _build("sdist", outdir)
    if result.returncode != 0:
        pytest.fail(
            "sdist build failed:\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    sdists = list(outdir.glob("*.tar.gz"))
    assert len(sdists) == 1, f"expected one sdist, got {sdists}"
    with tarfile.open(sdists[0]) as tf:
        # Strip the leading "amazon_ads_mcp-<version>/" component.
        names = {
            m.name.split("/", 1)[1]
            for m in tf.getmembers()
            if "/" in m.name
        }
    missing = [p for p in REQUIRED_IN_SDIST if p not in names]
    assert not missing, (
        f"sdist is missing staging sources: {missing}\n"
        "sdist->wheel rebuilds would ship zero API tools (issue #91)."
    )
