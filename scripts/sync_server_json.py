#!/usr/bin/env python3
"""Synchronize server.json with project version metadata."""

from __future__ import annotations

import argparse
import copy
import json
import re
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
SERVER_JSON = REPO_ROOT / "server.json"
PYPROJECT = REPO_ROOT / "pyproject.toml"


def _project_version(path: Path = PYPROJECT) -> str:
    in_project = False
    for line in path.read_text().splitlines():
        stripped = line.strip()
        if stripped == "[project]":
            in_project = True
            continue
        if in_project and stripped.startswith("["):
            break
        if in_project:
            match = re.fullmatch(r'version\s*=\s*"([^"]+)"', stripped)
            if match:
                return match.group(1)
    raise ValueError(f"{path} has no [project] version")


def _sync_data(data: dict[str, Any], version: str) -> dict[str, Any]:
    updated = copy.deepcopy(data)
    updated["version"] = version

    package_entries = updated.get("packages", [])
    if not isinstance(package_entries, list):
        raise ValueError("server.json packages must be a list when present")

    for package in package_entries:
        if not isinstance(package, dict):
            raise ValueError("server.json packages entries must be objects")
        package["version"] = version

    return updated


def sync_server_json() -> bool:
    """Update server.json.

    :return: True when the file changed, False when it was already current.
    """
    current = json.loads(SERVER_JSON.read_text())
    updated = _sync_data(current, _project_version())
    if current == updated:
        return False
    SERVER_JSON.write_text(json.dumps(updated, indent=2) + "\n")
    return True


def check_server_json() -> bool:
    """Return True when server.json already matches canonical metadata."""
    current = json.loads(SERVER_JSON.read_text())
    updated = _sync_data(current, _project_version())
    return current == updated


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Synchronize server.json with the project version."
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero if server.json is stale instead of rewriting it.",
    )
    args = parser.parse_args(argv)

    if args.check:
        if check_server_json():
            print("server.json is up to date")
            return 0
        print(
            "server.json is stale; run `python scripts/sync_server_json.py`",
            file=sys.stderr,
        )
        return 1

    changed = sync_server_json()
    print("server.json updated" if changed else "server.json already up to date")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
