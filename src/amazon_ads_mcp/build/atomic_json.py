"""Atomic JSON writer used by the v1 catalog refresh CLI.

Adapted from `.build/spec_utils/io.py:save_json`. The two meaningful
differences:

1. Commit uses `os.replace(tmp, target)` rather than `tmp.replace(target)`.
   Tests in Phase B monkeypatch `amazon_ads_mcp.build.atomic_json.os.replace`
   to simulate mid-commit crashes; keeping the call at the module level
   preserves that test seam.
2. Parent directories are created on demand so the CLI can write into a
   fresh destination.

Formatting is locked for determinism: sorted keys, 2-space indent,
`ensure_ascii=False`, trailing newline. Two writes with identical input
produce a byte-identical output.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Mapping


def save_json_atomic(path: Path, data: Mapping[str, Any]) -> None:
    """Write *data* to *path* atomically with deterministic formatting."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True, ensure_ascii=False)
            f.write("\n")
        # NOTE: keep as `os.replace(tmp, path)` so tests can monkeypatch
        # amazon_ads_mcp.build.atomic_json.os.replace to simulate crashes.
        os.replace(tmp, path)
    except Exception:
        # Best-effort cleanup: if the write failed before commit, remove
        # the half-written tmp so the target directory is clean.
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass
        raise
