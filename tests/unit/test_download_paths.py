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
