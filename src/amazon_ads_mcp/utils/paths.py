"""Path-containment helpers for user-supplied file paths.

Provides :func:`safe_join_within`, a single source of truth for resolving
a user-supplied relative path against a base directory and ensuring the
result stays inside that base directory (symlink-aware).

The MCP file download tools and the corresponding HTTP routes must share
this logic so that both control-plane and data-plane paths reject the
same traversal attempts.
"""

from __future__ import annotations

from pathlib import Path, PurePosixPath


class PathTraversalError(ValueError):
    """Raised when a user-supplied path escapes its base directory."""


def safe_join_within(base: Path, user_path: str) -> Path:
    """Join *user_path* to *base* and verify the result stays inside *base*.

    The check is symlink-aware: both the joined path and the base directory
    are fully resolved before the containment test. Absolute paths and
    paths containing explicit ``..`` components are rejected up front so
    the caller never touches the filesystem on an obviously malicious
    input.

    :param base: Trusted base directory.
    :type base: Path
    :param user_path: Caller-supplied relative path (e.g. from a tool
        argument or URL segment).
    :type user_path: str
    :return: Fully resolved path that is guaranteed to be inside
        ``base.resolve()``.
    :rtype: Path
    :raises PathTraversalError: If ``user_path`` is absolute, contains
        ``..`` components, or resolves outside *base*.
    """
    if not user_path:
        raise PathTraversalError("empty path")

    candidate = PurePosixPath(user_path.replace("\\", "/"))
    if candidate.is_absolute():
        raise PathTraversalError(f"absolute paths are not allowed: {user_path!r}")
    if any(part == ".." for part in candidate.parts):
        raise PathTraversalError(f"parent references are not allowed: {user_path!r}")

    base_resolved = base.resolve()
    joined = (base / user_path).resolve()
    try:
        joined.relative_to(base_resolved)
    except ValueError as exc:
        raise PathTraversalError(
            f"path {user_path!r} escapes base directory {base_resolved}"
        ) from exc
    return joined
