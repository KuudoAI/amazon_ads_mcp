"""Regression tests for MCP registry server.json sync."""

from __future__ import annotations

import json
import runpy
import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SERVER_JSON = REPO_ROOT / "server.json"
PYPROJECT = REPO_ROOT / "pyproject.toml"
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


def _sync_data(data: dict, version: str = "1.2.3"):
    return runpy.run_path(str(SYNC_SCRIPT))["_sync_data"](data, version)


def test_server_json_versions_match_pyproject():
    """Remote Registry metadata version must track the project version."""
    expected = _project_version()
    data = _server_json()

    assert data["version"] == expected


def test_server_json_is_remote_only():
    """The Registry contract advertises HTTP, not an installable package."""
    data = _server_json()

    assert "packages" not in data
    assert data["remotes"]


def test_sync_server_json_script_exists():
    """CI and release should call a reusable script, not duplicate JSON edits."""
    assert SYNC_SCRIPT.exists()


def test_server_json_advertises_streamable_http_remote_transport():
    """The registry metadata should expose the supported HTTP MCP endpoint."""
    data = _server_json()

    remotes = data.get("remotes", [])
    remote = next(
        remote
        for remote in remotes
        if remote["type"] == "streamable-http" and remote["url"].endswith("/mcp")
    )

    assert remote["url"] == "https://{HOSTNAME}/mcp"
    assert remote["variables"]["HOSTNAME"]["isRequired"] is True


def test_server_json_remote_uses_client_supplied_bearer_auth():
    data = _server_json()
    remote = data["remotes"][0]
    authorization = next(
        header for header in remote["headers"] if header["name"] == "Authorization"
    )

    assert authorization["value"] == "Bearer {AUTH_TOKEN}"
    assert authorization["variables"]["AUTH_TOKEN"]["isRequired"] is True
    assert authorization["variables"]["AUTH_TOKEN"]["isSecret"] is True


def test_sync_updates_remote_only_version_without_mutating_remote():
    data = {
        "version": "0.0.1",
        "remotes": [
            {
                "type": "streamable-http",
                "url": "https://ads.example.com/mcp",
            }
        ],
    }

    updated = _sync_data(data)

    assert updated == {
        "version": "1.2.3",
        "remotes": [
            {
                "type": "streamable-http",
                "url": "https://ads.example.com/mcp",
            }
        ],
    }
