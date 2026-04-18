"""Tests for the atomic JSON writer used by the v1 catalog refresh CLI.

Locked contract from adsv1.md §B.1: deterministic formatting (sorted keys,
stable indent, trailing newline), atomic commit via os.replace (NOT
Path.replace — see B.3 monkeypatch seam), tmp file removed on success,
idempotent writes produce zero diff.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from amazon_ads_mcp.build.atomic_json import save_json_atomic


def test_produces_sorted_keys_stable_indent_trailing_newline(tmp_path: Path):
    target = tmp_path / "out.json"
    save_json_atomic(target, {"b": 2, "a": 1, "nested": {"z": True, "y": False}})

    text = target.read_text()
    # Trailing newline
    assert text.endswith("\n")
    # Sorted keys
    parsed = json.loads(text)
    assert list(parsed.keys()) == ["a", "b", "nested"]
    assert list(parsed["nested"].keys()) == ["y", "z"]
    # Stable indent (2 spaces, per reused template)
    assert '\n  "a": 1,' in text


def test_tmp_file_absent_on_success(tmp_path: Path):
    target = tmp_path / "out.json"
    tmp_path_tmp = Path(str(target) + ".tmp")

    save_json_atomic(target, {"a": 1})

    assert target.exists(), "target file should be present"
    assert not tmp_path_tmp.exists(), f"tmp should be gone, found {tmp_path_tmp}"


def test_idempotent_writes(tmp_path: Path):
    """Two writes with same input → zero-byte diff. Refresh idempotency primitive."""
    target = tmp_path / "out.json"
    data = {"key": "value", "list": [1, 2, 3]}

    save_json_atomic(target, data)
    first = target.read_bytes()
    save_json_atomic(target, data)
    second = target.read_bytes()

    assert first == second


def test_commit_uses_module_level_os_replace(monkeypatch, tmp_path: Path):
    """The commit must call os.replace (module-level), not Path.replace.

    B.3 monkeypatches os.replace to simulate crashes mid-commit; this test
    protects that test seam. If the helper ever switches to Path.replace,
    that crash test silently becomes a no-op.
    """
    target = tmp_path / "out.json"
    calls: list[tuple[str, str]] = []

    real_replace = os.replace

    def spying_replace(src, dst):
        calls.append((str(src), str(dst)))
        return real_replace(src, dst)

    monkeypatch.setattr("amazon_ads_mcp.build.atomic_json.os.replace", spying_replace)

    save_json_atomic(target, {"a": 1})

    assert len(calls) == 1, f"expected one os.replace call, got {calls}"
    src, dst = calls[0]
    assert src.endswith(".tmp")
    assert dst == str(target)


def test_crash_before_replace_leaves_tmp_but_no_target(monkeypatch, tmp_path: Path):
    """If os.replace raises, target must not be corrupted.

    Atomic-write protocol protection: the tmp file may linger (swept on next
    refresh start per §4.9 step 1) but the target remains in its prior state.
    """
    target = tmp_path / "out.json"

    def exploding_replace(src, dst):
        raise OSError("simulated mid-commit crash")

    monkeypatch.setattr("amazon_ads_mcp.build.atomic_json.os.replace", exploding_replace)

    with pytest.raises(OSError, match="simulated mid-commit crash"):
        save_json_atomic(target, {"a": 1})

    assert not target.exists(), "target must not exist when replace fails"


def test_ensure_ascii_false_preserves_unicode(tmp_path: Path):
    """Non-ASCII chars stored verbatim (matches reused template)."""
    target = tmp_path / "out.json"
    save_json_atomic(target, {"name": "café"})
    assert "café" in target.read_text()


def test_creates_parent_dirs_if_missing(tmp_path: Path):
    """Target directory creation is a convenience the CLI relies on."""
    target = tmp_path / "nested" / "deeper" / "out.json"
    save_json_atomic(target, {"a": 1})
    assert target.exists()
