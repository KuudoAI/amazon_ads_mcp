"""Path-containment tests for file download tools.

These tests exercise :func:`amazon_ads_mcp.utils.paths.safe_join_within`
directly and through the two consumers that must apply it:

* :func:`amazon_ads_mcp.tools.download_tools.get_download_metadata`
* the MCP ``get_download_url`` tool (the body lives in
  ``server/builtin_tools.py``; we exercise the same containment code
  path by invoking ``safe_join_within`` the same way the tool does).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from fastmcp import FastMCP

from amazon_ads_mcp.tools import download_tools
from amazon_ads_mcp.utils.paths import PathTraversalError, safe_join_within


class _FakeHandler:
    def __init__(self, base_dir: Path) -> None:
        self.base_dir = base_dir


@pytest.fixture()
def profile_tree(tmp_path: Path) -> tuple[Path, str]:
    profile_id = "test_profile"
    (tmp_path / "profiles" / profile_id / "exports" / "campaigns").mkdir(parents=True)
    return tmp_path, profile_id


# ---------------------------------------------------------------------------
# safe_join_within
# ---------------------------------------------------------------------------


def test_safe_join_within_accepts_relative_nested(profile_tree):
    base, profile_id = profile_tree
    profile_dir = base / "profiles" / profile_id
    file_path = profile_dir / "exports" / "campaigns" / "ok.json"
    file_path.write_text("x")

    result = safe_join_within(profile_dir, "exports/campaigns/ok.json")
    assert result == file_path.resolve()


def test_safe_join_within_rejects_absolute(profile_tree):
    base, profile_id = profile_tree
    profile_dir = base / "profiles" / profile_id
    with pytest.raises(PathTraversalError):
        safe_join_within(profile_dir, "/etc/passwd")


def test_safe_join_within_rejects_dot_dot(profile_tree):
    base, profile_id = profile_tree
    profile_dir = base / "profiles" / profile_id
    for bad in ("../escape.csv", "a/../../escape.csv", "..\\escape"):
        with pytest.raises(PathTraversalError):
            safe_join_within(profile_dir, bad)


def test_safe_join_within_rejects_empty(profile_tree):
    base, profile_id = profile_tree
    profile_dir = base / "profiles" / profile_id
    with pytest.raises(PathTraversalError):
        safe_join_within(profile_dir, "")


@pytest.mark.skipif(
    sys.platform == "win32", reason="symlinks require admin on Windows"
)
def test_safe_join_within_rejects_symlink_escape(tmp_path: Path):
    profile_dir = tmp_path / "profiles" / "p1"
    profile_dir.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "secret.txt"
    secret.write_text("top-secret")

    # Symlink inside the profile dir pointing outside it.
    link = profile_dir / "link"
    os.symlink(outside, link)

    with pytest.raises(PathTraversalError):
        safe_join_within(profile_dir, "link/secret.txt")


# ---------------------------------------------------------------------------
# get_download_metadata
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_download_metadata_rejects_absolute(monkeypatch, profile_tree):
    base, profile_id = profile_tree
    monkeypatch.setattr(
        download_tools, "get_download_handler", lambda: _FakeHandler(base)
    )

    result = await download_tools.get_download_metadata(
        "/etc/passwd", profile_id=profile_id
    )
    assert result["success"] is False
    assert result["error"] == "Invalid file path"


@pytest.mark.asyncio
async def test_get_download_metadata_rejects_traversal(monkeypatch, profile_tree):
    base, profile_id = profile_tree
    monkeypatch.setattr(
        download_tools, "get_download_handler", lambda: _FakeHandler(base)
    )

    result = await download_tools.get_download_metadata(
        "../../outside.csv", profile_id=profile_id
    )
    assert result["success"] is False
    assert result["error"] == "Invalid file path"


@pytest.mark.asyncio
async def test_get_download_metadata_accepts_nested(monkeypatch, profile_tree):
    base, profile_id = profile_tree
    target = base / "profiles" / profile_id / "exports" / "campaigns" / "e.csv"
    target.write_text("data")
    target.with_suffix(".meta.json").write_text('{"k": "v"}')

    monkeypatch.setattr(
        download_tools, "get_download_handler", lambda: _FakeHandler(base)
    )

    result = await download_tools.get_download_metadata(
        "exports/campaigns/e.csv", profile_id=profile_id
    )
    assert result["success"] is True
    assert result["metadata"]["k"] == "v"


# ---------------------------------------------------------------------------
# get_download_url tool: base-URL resolution must not trust forged headers
#
# These drive the real tool body (registered on a FastMCP server, invoked via
# ``tool.fn``) so a regression that reintroduces inline X-Forwarded-* trust is
# caught at the wire path, not just in the ``_get_base_url`` helper.
# ---------------------------------------------------------------------------


class _FakeRequest:
    """Minimal stand-in for a Starlette Request as used by the tool."""

    def __init__(self, base_url: str, headers: dict[str, str]) -> None:
        self.base_url = base_url
        self.headers = headers


class _FakeAuthManager:
    def __init__(self, profile_id: str) -> None:
        self._profile_id = profile_id

    def get_active_profile_id(self) -> str:
        return self._profile_id


async def _get_download_url_tool():
    from amazon_ads_mcp.server.builtin_tools import register_download_tools

    server = FastMCP("test-ads")
    await register_download_tools(server)
    tool = await server.get_tool("get_download_url")
    assert tool is not None, "get_download_url should be registered"
    return tool


def _wire_tool_deps(monkeypatch, base: Path, profile_id: str, request: _FakeRequest):
    """Patch the tool's runtime dependencies to drive its body offline.

    Call this *after* fetching the tool: patching ``get_http_request`` earlier
    also intercepts FastMCP's auth-context lookup inside ``get_tool``, which
    expects a real request scope.
    """
    import amazon_ads_mcp.server.builtin_tools as builtin_tools
    import amazon_ads_mcp.utils.export_download_handler as edh
    import fastmcp.server.dependencies as deps

    # The tool reads the HTTP request via a local import of get_http_request;
    # patch the source module so the local import picks up our fake.
    monkeypatch.setattr(deps, "get_http_request", lambda: request)
    monkeypatch.setattr(
        builtin_tools, "get_auth_manager", lambda: _FakeAuthManager(profile_id)
    )
    monkeypatch.setattr(edh, "get_download_handler", lambda: _FakeHandler(base))


def _make_profile_file(base: Path, profile_id: str) -> str:
    rel = "exports/campaigns/report.json"
    target = base / "profiles" / profile_id / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("{}")
    return rel


@pytest.mark.asyncio
async def test_get_download_url_ignores_forged_headers_by_default(
    monkeypatch, tmp_path
):
    """Without AMAZON_ADS_TRUST_FORWARDED_HEADERS, a client cannot steer the
    generated download URL to an attacker host via X-Forwarded-* headers."""
    monkeypatch.delenv("AMAZON_ADS_TRUST_FORWARDED_HEADERS", raising=False)
    monkeypatch.delenv("AMAZON_ADS_PUBLIC_BASE_URL", raising=False)

    profile_id = "test_profile"
    rel = _make_profile_file(tmp_path, profile_id)
    request = _FakeRequest(
        base_url="http://localhost:9080/",
        headers={
            "X-Forwarded-Proto": "https",
            "X-Forwarded-Host": "attacker.example.com",
        },
    )
    tool = await _get_download_url_tool()
    _wire_tool_deps(monkeypatch, tmp_path, profile_id, request)
    result = await tool.fn(ctx=None, file_path=rel)

    assert result.success is True
    assert "attacker.example.com" not in result.download_url
    assert result.download_url.startswith("http://localhost:9080/downloads/")


@pytest.mark.asyncio
async def test_get_download_url_honors_forwarded_when_trusted(monkeypatch, tmp_path):
    """When the operator opts in, the proxy's X-Forwarded-* headers are used —
    proving the hardening is non-breaking for correctly configured proxies."""
    monkeypatch.setenv("AMAZON_ADS_TRUST_FORWARDED_HEADERS", "true")
    monkeypatch.delenv("AMAZON_ADS_PUBLIC_BASE_URL", raising=False)

    profile_id = "test_profile"
    rel = _make_profile_file(tmp_path, profile_id)
    request = _FakeRequest(
        base_url="http://localhost:9080/",
        headers={
            "X-Forwarded-Proto": "https",
            "X-Forwarded-Host": "ads.example.com",
        },
    )
    tool = await _get_download_url_tool()
    _wire_tool_deps(monkeypatch, tmp_path, profile_id, request)
    result = await tool.fn(ctx=None, file_path=rel)

    assert result.success is True
    assert result.download_url.startswith("https://ads.example.com/downloads/")


@pytest.mark.asyncio
async def test_get_download_url_public_base_url_wins(monkeypatch, tmp_path):
    """An explicit public base URL overrides even trusted forwarded headers."""
    monkeypatch.setenv("AMAZON_ADS_PUBLIC_BASE_URL", "https://canonical.example.com/")
    monkeypatch.setenv("AMAZON_ADS_TRUST_FORWARDED_HEADERS", "true")

    profile_id = "test_profile"
    rel = _make_profile_file(tmp_path, profile_id)
    request = _FakeRequest(
        base_url="http://localhost:9080/",
        headers={
            "X-Forwarded-Proto": "https",
            "X-Forwarded-Host": "attacker.example.com",
        },
    )
    tool = await _get_download_url_tool()
    _wire_tool_deps(monkeypatch, tmp_path, profile_id, request)
    result = await tool.fn(ctx=None, file_path=rel)

    assert result.success is True
    assert result.download_url.startswith(
        "https://canonical.example.com/downloads/"
    )
    assert "attacker.example.com" not in result.download_url
