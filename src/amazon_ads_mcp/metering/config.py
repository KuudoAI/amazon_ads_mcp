"""Resolves ``metering.yaml``'s path across dev and packaged deployments
(fix round 2, deployment gap #1).

Docker/wheel deployments never carry the repo-root ``metering.yaml`` --
the Docker runtime image copies the venv + ``dist/openapi`` + the
entrypoint into ``/app``, not a repo checkout (see ``Dockerfile``), and a
wheel install (``pip install 'amazon-ads-mcp[metering]'``) only ships
files that are actually packaged. Resolution order:

1. ``METERING_CONFIG`` env var, if set -- an explicit operator override,
   used verbatim (interpreted relative to CWD if not absolute, exactly
   like every other bare ``Path(...)`` use in this codebase).
2. ``./metering.yaml`` relative to CWD, if that file exists -- dev
   convenience: running from a repo checkout finds the tracked
   repo-root file with zero configuration.
3. The packaged copy at ``amazon_ads_mcp/metering/metering.yaml``,
   resolved via :mod:`importlib.resources` -- works from a wheel install
   AND from a Docker image's site-packages, independent of CWD. This
   copy is byte-identical to the repo-root file (see
   ``tests/metering/test_packaged_config.py``'s drift guard, which fails
   loudly if the two ever diverge).

This module has no dependency on ``mcp_outbound_metering`` -- only on
``importlib.resources`` (stdlib) -- so it stays importable on every
Python version, same as ``normalizer.py``/``context.py``.
"""

from __future__ import annotations

from importlib import resources
from pathlib import Path
from typing import Mapping

__all__ = ["resolve_config_path"]

_CONFIG_FILENAME = "metering.yaml"
_PACKAGE = "amazon_ads_mcp.metering"


def resolve_config_path(env: Mapping[str, str]) -> Path:
    """Resolve ``metering.yaml``'s path per the module docstring's
    3-step order. Read-only -- never writes, never creates a file."""
    explicit = env.get("METERING_CONFIG")
    if explicit:
        return Path(explicit)

    cwd_relative = Path(_CONFIG_FILENAME)
    if cwd_relative.is_file():
        return cwd_relative

    return _packaged_config_path()


def _packaged_config_path() -> Path:
    """The packaged ``metering.yaml``, as a real filesystem
    :class:`~pathlib.Path`.

    :func:`importlib.resources.as_file` is a no-op for a normal (non-zip)
    package install -- the file is already a real path on disk, and
    nothing is deleted when the context manager exits. That covers every
    deployment shape this project actually uses: a ``uv sync``'d Docker
    image and a plain ``pip``/``uv``-installed wheel both extract into
    site-packages as regular files, never a zipped/zipimport-style
    install. This function reads ``metering.yaml`` exactly once per
    process, synchronously, at startup (via
    ``MeteringRuntime.from_config``), so eagerly resolving and returning
    the path here -- rather than requiring every caller to hold the
    ``as_file`` context manager open for the life of the process -- is
    safe for this deployment model.
    """
    ref = resources.files(_PACKAGE).joinpath(_CONFIG_FILENAME)
    with resources.as_file(ref) as path:
        return path
