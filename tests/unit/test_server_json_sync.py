"""Regression tests for MCP registry server.json sync."""

from __future__ import annotations

import json
import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SERVER_JSON = REPO_ROOT / "server.json"
PYPROJECT = REPO_ROOT / "pyproject.toml"
PACKAGES_JSON = REPO_ROOT / "openapi" / "resources" / "packages.json"
SYNC_SCRIPT = REPO_ROOT / "scripts" / "sync_server_json.py"


def _project_version() -> str:
    in_project = False
    for line in PYPROJECT.read_text().splitlines():
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
    raise AssertionError("pyproject.toml has no [project] version")


def _server_json() -> dict:
    return json.loads(SERVER_JSON.read_text())


def test_server_json_versions_match_pyproject():
    """Registry metadata version must track the package version."""
    expected = _project_version()
    data = _server_json()

    assert data["version"] == expected
    assert data["packages"], "server.json must declare at least one package"
    for package in data["packages"]:
        assert package["version"] == expected


def test_server_json_allowed_packages_match_catalog():
    """AMAZON_AD_API_PACKAGES allowedValues must mirror packages.json."""
    expected = sorted(json.loads(PACKAGES_JSON.read_text())["packages"])
    data = _server_json()
    env_vars = data["packages"][0]["environmentVariables"]
    packages_var = next(
        item for item in env_vars if item["name"] == "AMAZON_AD_API_PACKAGES"
    )

    assert packages_var["allowedValues"] == expected


def test_sync_server_json_script_exists():
    """CI and release should call a reusable script, not duplicate JSON edits."""
    assert SYNC_SCRIPT.exists()
