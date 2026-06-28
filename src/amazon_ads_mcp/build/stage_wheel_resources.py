"""Stage runtime OpenAPI resources into the package tree for wheel builds.

The canonical home for built OpenAPI deployment artifacts is
``dist/openapi/resources/`` (specs + media/manifest/transform sidecars +
``packages.json``) and ``dist/openapi/overlays/`` (hand-authored arg-alias
overlays). Both are committed. The Docker image copies those directories
directly and runs the server from a working directory where the runtime
loader (``ServerBuilder._mount_resource_servers`` /
``_register_sidecar_middleware``) finds them under ``dist/openapi/``.

A ``pip install`` has no such working directory. The runtime loader's final
fallback is the packaged ``amazon_ads_mcp/resources/`` directory shipped
inside the wheel. Historically only the adsv1 field catalog and the
JSON-schema contract shipped there, so pip installs mounted **zero** OpenAPI
specs and exposed only builtin tools (issue #91).

This module stages the dist artifacts into the package tree at *build time*
so the wheel ships a self-contained resource set, while keeping those copies
out of source control (``.gitignore`` ignores top-level
``src/amazon_ads_mcp/resources/*.json`` and ``resources/overlays/``). The
files are regenerated from ``dist/`` on every build, so committing them
would only invite drift.

It is invoked by the release workflow and the wheel-content test *before*
building the wheel. Building the wheel directly from the source tree
(``python -m build --wheel`` / ``uv build --wheel``) picks the staged files
up via the existing ``[[tool.poetry.include]]`` globs in ``pyproject.toml``.

The operation is idempotent and a graceful no-op when the dist source is
absent (e.g. the Docker builder stage runs ``uv sync`` before ``dist/`` is
copied in — and never needs the staged copies because it mounts from
``dist/openapi/`` at runtime).

Usage::

    python -m amazon_ads_mcp.build.stage_wheel_resources           # stage
    python -m amazon_ads_mcp.build.stage_wheel_resources --clean   # remove
    python -m amazon_ads_mcp.build.stage_wheel_resources --check   # verify src present
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

# repo_root/src/amazon_ads_mcp/build/stage_wheel_resources.py
#   parents[0]=build  [1]=amazon_ads_mcp  [2]=src  [3]=repo root
_REPO_ROOT = Path(__file__).resolve().parents[3]

DEFAULT_RESOURCES_SRC = _REPO_ROOT / "dist" / "openapi" / "resources"
DEFAULT_OVERLAYS_SRC = _REPO_ROOT / "dist" / "openapi" / "overlays"
DEFAULT_DEST = _REPO_ROOT / "src" / "amazon_ads_mcp" / "resources"

# Subdirectories under the package resources dir that are committed and must
# never be touched by staging/cleaning.
_PROTECTED_SUBDIRS = ("adsv1", "contract")


def _copy_flat_json(src_dir: Path, dest_dir: Path) -> int:
    """Copy every top-level ``*.json`` from *src_dir* into *dest_dir*.

    Returns the number of files copied. Subdirectories are ignored — the
    dist resources directory is flat.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    count = 0
    for path in sorted(src_dir.glob("*.json")):
        if not path.is_file():
            continue
        shutil.copy2(path, dest_dir / path.name)
        count += 1
    return count


def stage(
    resources_src: Path = DEFAULT_RESOURCES_SRC,
    overlays_src: Path = DEFAULT_OVERLAYS_SRC,
    dest: Path = DEFAULT_DEST,
) -> dict[str, int]:
    """Stage dist OpenAPI artifacts into the package resources directory.

    :param resources_src: ``dist/openapi/resources`` (specs + sidecars +
        ``packages.json``).
    :param overlays_src: ``dist/openapi/overlays`` (arg-alias overlays).
    :param dest: ``src/amazon_ads_mcp/resources`` — the packaged resources
        directory shipped in the wheel.
    :return: Counts ``{"resources": N, "overlays": M}``. Both zero when the
        dist source is absent (graceful no-op).
    """
    if not resources_src.exists():
        # Docker builder path, or a checkout without a built dist/. The
        # wheel produced here simply falls back to dist/openapi/ at runtime.
        print(
            f"[stage_wheel_resources] source {resources_src} absent; "
            "nothing to stage (this is expected in the Docker builder).",
            file=sys.stderr,
        )
        return {"resources": 0, "overlays": 0}

    n_res = _copy_flat_json(resources_src, dest)

    n_ovl = 0
    if overlays_src.exists():
        n_ovl = _copy_flat_json(overlays_src, dest / "overlays")

    print(
        f"[stage_wheel_resources] staged {n_res} resource file(s) and "
        f"{n_ovl} overlay file(s) into {dest}"
    )
    return {"resources": n_res, "overlays": n_ovl}


def clean(dest: Path = DEFAULT_DEST) -> int:
    """Remove staged files, leaving committed subpackages intact.

    Deletes top-level ``*.json`` and the ``overlays/`` subdir under *dest*
    (the only things staging creates). The committed ``adsv1/`` and
    ``contract/`` subpackages are never touched.

    :return: Number of top-level JSON files removed.
    """
    removed = 0
    if dest.exists():
        for path in dest.glob("*.json"):
            if path.is_file():
                path.unlink()
                removed += 1
        overlays = dest / "overlays"
        if overlays.is_dir() and overlays.name not in _PROTECTED_SUBDIRS:
            shutil.rmtree(overlays)
    print(f"[stage_wheel_resources] removed {removed} staged resource file(s)")
    return removed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Stage dist OpenAPI resources into the package tree for wheel "
            "builds (issue #91 packaging fix)."
        )
    )
    parser.add_argument(
        "--resources-src",
        type=Path,
        default=DEFAULT_RESOURCES_SRC,
        help="dist/openapi/resources directory (default: repo dist tree).",
    )
    parser.add_argument(
        "--overlays-src",
        type=Path,
        default=DEFAULT_OVERLAYS_SRC,
        help="dist/openapi/overlays directory (default: repo dist tree).",
    )
    parser.add_argument(
        "--dest",
        type=Path,
        default=DEFAULT_DEST,
        help="Packaged resources directory (default: src/amazon_ads_mcp/resources).",
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Remove staged files instead of staging them.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help=(
            "Exit non-zero if the dist resources source is missing or empty. "
            "Use as a release pre-flight."
        ),
    )
    args = parser.parse_args(argv)

    if args.clean:
        clean(args.dest)
        return 0

    if args.check:
        specs = (
            sorted(args.resources_src.glob("*.json"))
            if args.resources_src.exists()
            else []
        )
        if not specs:
            print(
                f"[stage_wheel_resources] CHECK FAILED: no specs under "
                f"{args.resources_src}",
                file=sys.stderr,
            )
            return 1
        print(
            f"[stage_wheel_resources] CHECK OK: {len(specs)} resource file(s) "
            f"available under {args.resources_src}"
        )
        return 0

    stage(args.resources_src, args.overlays_src, args.dest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
