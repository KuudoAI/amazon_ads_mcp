"""Minimal presence check for new CI jobs (adsv1.md §F.1).

Asserts only job-name presence under `jobs:` in .github/workflows/ci.yml.
Does NOT validate structure, steps, matrix, or action versions — those
change legitimately and would produce noise. actionlint (or similar) is
the right tool for deeper YAML validation; if added, attach it as a
separate CI step.
"""

from __future__ import annotations

from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")  # PyYAML ships with the project already.

WORKFLOWS_DIR = Path(__file__).resolve().parents[2] / ".github" / "workflows"
CI_PATH = WORKFLOWS_DIR / "ci.yml"
RELEASE_PATH = WORKFLOWS_DIR / "release.yml"

REQUIRED_JOBS = {
    # catalog-drift and catalog-idempotency intentionally excluded —
    # they consume private source specs under .build/adsv1_specs/ and
    # are run by maintainers locally, not in public CI.
    "catalog-negative",
    "wheel-smoke",
}


def test_ci_workflow_contains_required_jobs():
    assert CI_PATH.exists(), f"expected CI workflow at {CI_PATH}"
    data = yaml.safe_load(CI_PATH.read_text())
    jobs = data.get("jobs") or {}
    missing = REQUIRED_JOBS - jobs.keys()
    assert not missing, f"missing required CI jobs: {sorted(missing)}"


def test_release_stages_resources_before_building_wheel():
    """Release must stage OpenAPI resources before building, from source.

    Guards the issue #91 packaging fix: if the staging step is dropped, or
    the build reverts to the default sdist->wheel path (which drops the
    gitignored staged files), the published wheel registers 0 API tools.
    A presence + ordering check on the build step keeps this from silently
    regressing.
    """
    assert RELEASE_PATH.exists(), f"expected release workflow at {RELEASE_PATH}"
    text = RELEASE_PATH.read_text()

    stage_marker = "stage_wheel_resources.py"
    build_marker = "build --sdist --wheel"

    assert stage_marker in text, (
        "release.yml must run stage_wheel_resources before building "
        "(issue #91); marker not found"
    )
    assert build_marker in text, (
        "release.yml must build the wheel from source via "
        f"`python -m build --sdist --wheel` (issue #91); '{build_marker}' "
        "not found — the default sdist->wheel path drops staged resources"
    )
    assert text.index(stage_marker) < text.index(build_marker), (
        "release.yml runs the wheel build before staging resources; "
        "staging must come first (issue #91)"
    )
