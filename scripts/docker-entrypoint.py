#!/usr/bin/env python3
"""Prepare writable Docker volumes, then run the server as the app user."""

from __future__ import annotations

import os
import pwd
import stat
import sys
from pathlib import Path


APP_USER = "app"
DEFAULT_RUNTIME_DIRS = ("/app/.cache",)
DEFAULT_SHARED_SUBDIRS = ("/app/data/uploads",)


def _runtime_dirs() -> list[Path]:
    dirs = {Path(p) for p in DEFAULT_RUNTIME_DIRS}
    for value in DEFAULT_SHARED_SUBDIRS:
        dirs.add(Path(value))
    for env_name in ("AMAZON_ADS_DOWNLOAD_DIR", "AMAZON_ADS_CACHE_DIR"):
        value = os.environ.get(env_name)
        if value and Path(value) != Path("/app/data"):
            dirs.add(Path(value))
    return sorted(dirs)


def _chmod_writable(path: Path) -> None:
    mode = path.stat().st_mode
    if path.is_dir():
        mode |= stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR
        mode |= stat.S_IRGRP | stat.S_IXGRP
    else:
        mode |= stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP
    os.chmod(path, mode)


def _prepare_path(path: Path, uid: int, gid: int) -> None:
    path.mkdir(parents=True, exist_ok=True)
    for root, dirs, files in os.walk(path):
        root_path = Path(root)
        os.chown(root_path, uid, gid)
        _chmod_writable(root_path)
        for name in dirs:
            child = root_path / name
            os.chown(child, uid, gid)
            _chmod_writable(child)
        for name in files:
            child = root_path / name
            os.chown(child, uid, gid)
            _chmod_writable(child)


def _drop_privileges(uid: int, gid: int) -> None:
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)
    os.environ["HOME"] = "/app"
    os.environ.setdefault("XDG_CACHE_HOME", "/app/.cache")
    os.environ.setdefault("XDG_DATA_HOME", "/app/.local/share")


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit("usage: docker-entrypoint.py <command> [args...]")

    if os.geteuid() == 0:
        user = pwd.getpwnam(APP_USER)
        for path in _runtime_dirs():
            _prepare_path(path, user.pw_uid, user.pw_gid)
        _drop_privileges(user.pw_uid, user.pw_gid)

    os.execvp(sys.argv[1], sys.argv[1:])


if __name__ == "__main__":
    main()
