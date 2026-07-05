"""Parity guard: source and dist copies of packages.json must match.

The runtime loader prefers ``dist/openapi/resources/packages.json`` whenever
``dist/`` exists (always true in a checkout and in Docker), and the wheel
stages its copy FROM dist/. An edit to ``openapi/resources/packages.json``
that skips the dist regen is therefore silently dead at runtime — exactly
how the ``defaults`` list shipped as ``[]`` while the source said otherwise.
This test makes that drift loud.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE = REPO_ROOT / "openapi" / "resources" / "packages.json"
DIST = REPO_ROOT / "dist" / "openapi" / "resources" / "packages.json"


@pytest.mark.skipif(
    not (SOURCE.exists() and DIST.exists()),
    reason="repo checkout with both packages.json copies required",
)
def test_source_and_dist_packages_json_match():
    src = json.loads(SOURCE.read_text())
    dst = json.loads(DIST.read_text())
    differing = sorted(
        k for k in set(src) | set(dst) if src.get(k) != dst.get(k)
    )
    assert not differing, (
        f"packages.json drift between source and dist on keys {differing}: "
        "the runtime reads the dist copy — regenerate it (or cp the source "
        "over it) so edits actually ship."
    )


@pytest.mark.skipif(not DIST.exists(), reason="repo checkout required")
def test_every_alias_namespace_has_a_committed_spec():
    """Each packages.json alias must resolve to a spec file that ships.

    dist/.gitignore ignores everything under dist/ (committed files were
    force-added), so a regenerated spec can exist locally while fresh
    clones — including the release workflow — silently lack it. That is
    how AdsAPIv1All/AdsAPIv1Beta/Conversions/CampaignConversionTracking
    shipped as aliases without spec files. On a clean checkout this test
    fails for any alias whose spec was never `git add -f`-ed.
    """
    pkgs = json.loads(DIST.read_text())
    resources_dir = DIST.parent
    missing = sorted(
        ns
        for ns in set((pkgs.get("aliases") or {}).values())
        if not (resources_dir / f"{ns}.json").exists()
    )
    assert not missing, (
        f"aliases point at spec files absent from this checkout: {missing} "
        "— regenerate and force-add them (dist/.gitignore ignores dist/*)."
    )
