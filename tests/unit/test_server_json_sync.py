"""Regression tests for MCP registry server.json sync."""

from __future__ import annotations

import json
import runpy
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


def _sync_data(data: dict, version: str = "1.2.3", packages: list[str] | None = None):
    return runpy.run_path(str(SYNC_SCRIPT))["_sync_data"](
        data, version, packages or ["profiles"]
    )


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


def test_server_json_advertises_stdio_package_transport():
    """The PyPI package can be launched locally over stdio."""
    data = _server_json()

    assert any(
        package["registryType"] == "pypi"
        and package["identifier"] == "amazon-ads-mcp"
        and package["transport"]["type"] == "stdio"
        for package in data["packages"]
    )


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


def test_server_json_advertises_kuudo_configuration():
    data = _server_json()
    env_vars = {
        item["name"]: item for item in data["packages"][0]["environmentVariables"]
    }

    assert "kuudo" in env_vars["AMAZON_ADS_AUTH_METHOD"]["description"]
    assert env_vars["KUUDO_API_BASE_URL"]["isSecret"] is False
    assert env_vars["KUUDO_API_KEY"]["isSecret"] is True
    assert env_vars["KUUDO_PROVIDER"]["default"] == "amazon_ads"
    assert env_vars["KUUDO_REMOTE_IDENTITY_ID"]["isRequired"] is False


def test_sync_replaces_stale_remote_metadata_without_duplicates():
    data = {
        "packages": [
            {
                "environmentVariables": [
                    {"name": "AMAZON_AD_API_PACKAGES", "allowedValues": []}
                ]
            }
        ],
        "remotes": [
            {
                "type": "streamable-http",
                "url": "https://{HOSTNAME}/mcp/",
                "variables": {"HOSTNAME": {"description": "stale"}},
            },
            {
                "type": "streamable-http",
                "url": "https://{HOSTNAME}/mcp",
                "variables": {"HOSTNAME": {"description": "duplicate"}},
            },
            {"type": "sse", "url": "https://legacy.example/sse"},
        ],
    }

    updated = _sync_data(data)

    assert updated["remotes"] == [
        {
            "type": "streamable-http",
            "url": "https://{HOSTNAME}/mcp",
            "variables": {
                "HOSTNAME": {
                    "description": "Hostname of a running Amazon Ads MCP HTTP deployment.",
                    "isRequired": True,
                    "placeholder": "ads.example.com",
                }
            },
        },
        {"type": "sse", "url": "https://legacy.example/sse"},
    ]
