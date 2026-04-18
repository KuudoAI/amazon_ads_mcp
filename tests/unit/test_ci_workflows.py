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

CI_PATH = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "ci.yml"

REQUIRED_JOBS = {
    "catalog-drift",
    "catalog-idempotency",
    "catalog-negative",
    "wheel-smoke",
}


def test_ci_workflow_contains_required_jobs():
    assert CI_PATH.exists(), f"expected CI workflow at {CI_PATH}"
    data = yaml.safe_load(CI_PATH.read_text())
    jobs = data.get("jobs") or {}
    missing = REQUIRED_JOBS - jobs.keys()
    assert not missing, f"missing required CI jobs: {sorted(missing)}"
