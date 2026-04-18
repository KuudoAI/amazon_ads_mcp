"""Wheel-content test: assert the packaged catalog JSON files ship in the wheel.

Marked @pytest.mark.slow because it shells out to `python -m build --wheel`.
Local dev: `uv run pytest -m "not slow"` skips this.
CI: `uv run pytest -m slow` runs it.

This test catches packaging backend misconfiguration (e.g., a
[[tool.poetry.include]] entry with the wrong path or format) that the
source-tree test suite cannot detect.
"""

from __future__ import annotations

import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

REQUIRED_IN_WHEEL = [
    "amazon_ads_mcp/resources/adsv1/dimensions.json",
    "amazon_ads_mcp/resources/adsv1/metrics.json",
    "amazon_ads_mcp/resources/adsv1/index.json",
    "amazon_ads_mcp/resources/adsv1/catalog_meta.json",
]


def _build_wheel(outdir: Path) -> subprocess.CompletedProcess:
    """Build a wheel using whichever builder is available: uv, then build.

    Prefers `uv build` since this project is uv-managed. Falls back to
    `python -m build` for environments that only have the PyPA build
    frontend installed.
    """
    if shutil.which("uv"):
        return subprocess.run(
            ["uv", "build", "--wheel", "--out-dir", str(outdir)],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )
    import sys
    return subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "--outdir", str(outdir)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )


@pytest.mark.slow
def test_built_wheel_contains_all_four_catalog_files(tmp_path: Path):
    """Build a real wheel and inspect it to verify catalog JSON files ship.

    Catches packaging-backend misconfiguration that source-tree tests miss.
    """
    result = _build_wheel(tmp_path)
    if result.returncode != 0:
        pytest.fail(
            f"wheel build failed:\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )

    wheels = list(tmp_path.glob("*.whl"))
    assert len(wheels) == 1, f"expected one wheel, got {wheels}"

    with zipfile.ZipFile(wheels[0]) as zf:
        names = set(zf.namelist())

    missing = [p for p in REQUIRED_IN_WHEEL if p not in names]
    assert not missing, (
        f"wheel is missing packaged catalog files: {missing}\n"
        f"wheel contents:\n" + "\n".join(sorted(names))
    )
