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


def normalize_to_profile_relative(base: Path, user_path: str) -> str:
    """Coerce *user_path* to a form consumable by :func:`safe_join_within`.

    The download tool surface emits profile-relative ``file_path`` as canonical
    (P0.3). But clients may pass an absolute path — either from legacy callers,
    from the additive ``file_path_absolute`` field, or from a hand-constructed
    script. This helper normalizes those absolute paths that resolve inside
    *base* to the equivalent relative form. Absolute paths that escape *base*,
    and any relative input, are returned unchanged (the strict
    :func:`safe_join_within` pass still runs downstream and rejects true
    traversal attempts).

    Both *base* and the candidate are ``.resolve()``-ed before the containment
    check so the function is deterministic regardless of the caller's CWD
    (tests launched from subdirectories, Docker working-dir drift, etc.).

    :param base: Profile base dir the path must stay inside.
    :param user_path: Raw string from the caller — relative or absolute.
    :return: A string that :func:`safe_join_within` can accept for relative
        inputs; or the original string for clearly-invalid inputs
        (which :func:`safe_join_within` will then reject cleanly).
    """
    if not user_path:
        return user_path
    candidate = Path(user_path)
    if not candidate.is_absolute():
        return user_path
    try:
        rel = candidate.resolve().relative_to(base.resolve())
    except ValueError:
        # Outside the profile — let safe_join_within reject with its usual error.
        return user_path
    return str(rel)


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
