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
DOCKERFILE_PATH = Path(__file__).resolve().parents[2] / "Dockerfile"
DOCKERIGNORE_PATH = Path(__file__).resolve().parents[2] / ".dockerignore"

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


def _release_build_step_script() -> str:
    """Return the `run` script of the release workflow's Build package step."""
    assert RELEASE_PATH.exists(), f"expected release workflow at {RELEASE_PATH}"
    data = yaml.safe_load(RELEASE_PATH.read_text())
    for job in (data.get("jobs") or {}).values():
        for step in job.get("steps") or []:
            run = step.get("run") or ""
            if "python -m build" in run:
                return run
    pytest.fail("release.yml has no step running `python -m build`")


def _workflow_run_scripts(path: Path) -> list[str]:
    """Return every non-empty run script from a workflow."""
    assert path.exists(), f"expected workflow at {path}"
    data = yaml.safe_load(path.read_text())
    scripts: list[str] = []
    for job in (data.get("jobs") or {}).values():
        for step in job.get("steps") or []:
            run = step.get("run")
            if run:
                scripts.append(run)
    return scripts


def test_release_preflights_resources_before_building():
    """Release must pre-flight dist resources before building both artifacts.

    Guards the issue #91 packaging fix: staging happens inside the
    build_package.py PEP 517 backend on every wheel build, so the release's
    job is (1) fail loudly via `--check` when dist/openapi is hollow and
    (2) build both sdist and wheel. Parsing the actual build step's `run`
    script (instead of whole-file text.index) keeps comments elsewhere in
    the workflow from satisfying or defeating the ordering check.
    """
    script = _release_build_step_script()

    check_marker = "stage_wheel_resources.py --check"
    build_marker = "build --sdist --wheel"

    assert check_marker in script, (
        "release.yml's build step must run the stage_wheel_resources.py "
        "--check pre-flight (issue #91); marker not found in the step script"
    )
    assert build_marker in script, (
        "release.yml must build both artifacts via "
        f"`python -m build --sdist --wheel` (issue #91); '{build_marker}' "
        "not found in the build step script"
    )
    assert script.index(check_marker) < script.index(build_marker), (
        "release.yml runs the build before the resource pre-flight; "
        "--check must come first so a hollow dist/ stops the release "
        "(issue #91)"
    )


def test_dockerfile_copies_in_tree_build_backend_before_project_install():
    """Docker project install needs build_package.py beside pyproject.toml."""
    assert DOCKERFILE_PATH.exists(), f"expected Dockerfile at {DOCKERFILE_PATH}"
    text = DOCKERFILE_PATH.read_text()

    backend_marker = "build_package.py"
    # Task 22 fix round 2: the project-install `uv sync` now builds its
    # --extra set dynamically ($EXTRAS: always code-mode, plus metering
    # when INCLUDE_METERING=true) rather than a fixed --extra code-mode
    # literal, so the marker matches the current (parameterized) command
    # rather than one specific extras combination.
    project_install_marker = "uv sync --no-dev --frozen $EXTRAS --no-editable"

    assert backend_marker in text, (
        "Dockerfile must copy build_package.py before installing the project; "
        "pyproject.toml uses it as an in-tree PEP 517 backend."
    )
    assert text.index(backend_marker) < text.rindex(project_install_marker), (
        "Dockerfile copies build_package.py after the project install; "
        "the in-tree build backend must be present before `uv sync` builds "
        "amazon-ads-mcp."
    )


def test_dockerignore_keeps_in_tree_build_backend():
    """Docker build context must include the in-tree PEP 517 backend."""
    assert DOCKERIGNORE_PATH.exists(), (
        f"expected .dockerignore at {DOCKERIGNORE_PATH}"
    )
    lines = {
        line.strip()
        for line in DOCKERIGNORE_PATH.read_text().splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }

    assert "!build_package.py" in lines, (
        ".dockerignore denies everything by default, so it must explicitly "
        "keep build_package.py for Docker's `COPY build_package.py ./` step."
    )


def test_ci_checks_server_json_sync():
    """CI must fail when server.json drifts from package metadata."""
    scripts = _workflow_run_scripts(CI_PATH)

    assert any("scripts/sync_server_json.py --check" in script for script in scripts)


def test_release_updates_and_commits_server_json():
    """Release version bump must update server.json before committing."""
    scripts = _workflow_run_scripts(RELEASE_PATH)
    update_script = next(
        script for script in scripts if "NEW_VERSION" in script and "pyproject.toml" in script
    )
    commit_script = next(script for script in scripts if "git commit -m" in script)

    assert "scripts/sync_server_json.py" in update_script
    assert update_script.index("scripts/sync_server_json.py") > update_script.index(
        "pyproject.toml"
    )
    assert "server.json" in commit_script
