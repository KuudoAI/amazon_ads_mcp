"""Single source of truth for locating OpenAPI resource directories.

Every consumer — tool mounting, sidecar transform middleware, the
packages.json prefix/allowlist loaders — resolves through these helpers so
specs and their sidecar transforms always come from the SAME tree. Before
consolidation each site hand-rolled its own candidate list with divergent
precedence (mount preferred dist/, the sidecar middleware preferred
openapi/, and two different packages.json orders existed), which on a
maintainer checkout silently paired minified dist specs with source-tree
transform rules.

Precedence, in order:

1. ``dist/openapi/...`` — the committed, minified deployment artifacts.
   Docker and repo checkouts run from here.
2. ``openapi/...`` — the maintainer source tree (gitignored, present only
   on machines that run the private regen pipeline).
3. The packaged ``amazon_ads_mcp/resources/`` directory — what wheels ship;
   the build_package.py backend stages dist/openapi into it at build time.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

__all__ = [
    "packaged_resources_dir",
    "resolve_resources_dir",
    "resolve_overlays_dir",
    "find_packages_json",
]


def packaged_resources_dir() -> Path:
    """Return the packaged ``amazon_ads_mcp/resources`` directory."""
    return Path(__file__).resolve().parent.parent / "resources"


def resolve_resources_dir() -> Optional[Path]:
    """Resolve the OpenAPI specs directory (dist -> source -> packaged)."""
    for candidate in (
        Path("dist/openapi/resources"),
        Path("openapi/resources"),
        packaged_resources_dir(),
    ):
        if candidate.exists():
            return candidate
    return None


def resolve_overlays_dir() -> Optional[Path]:
    """Resolve the arg-alias overlays directory (dist -> packaged).

    Overlays are hand-authored and live only under ``dist/openapi/overlays``
    (committed) or the staged ``resources/overlays`` copy inside a wheel.
    """
    for candidate in (
        Path("dist/openapi/overlays"),
        packaged_resources_dir() / "overlays",
    ):
        if candidate.exists():
            return candidate
    return None


def find_packages_json(resources_dir: Path) -> Optional[Path]:
    """Locate packages.json for a given resources directory.

    Lives inside the resources dir in every supported layout (dist, source,
    staged wheel); the parent-dir and ``openapi/packages.json`` fallbacks
    cover legacy generator layouts.
    """
    for candidate in (
        resources_dir / "packages.json",
        resources_dir.parent / "packages.json",
        Path("openapi/packages.json"),
    ):
        if candidate.exists():
            return candidate
    return None
