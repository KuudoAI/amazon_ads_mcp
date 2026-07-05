"""In-tree PEP 517 backend: stage OpenAPI resources, then delegate to poetry-core.

Wired via ``[build-system] build-backend = "build_package"`` with
``backend-path = ["."]``, so EVERY wheel/editable build — ``pip install .``
from a clone, ``pip install git+https://...``, a wheel built from the
published sdist, ``uv sync``/``uv build``, and the release workflow — stages
``dist/openapi/{resources,overlays}/`` into ``src/amazon_ads_mcp/resources/``
before poetry-core assembles the artifact. This closes the issue-#91 gap
where only the release workflow's choreographed stage-then-build recipe
produced a wheel with OpenAPI specs.

A ``[tool.poetry.build] script`` would achieve the same staging but marks the
wheel non-pure (platform-tagged); this shim keeps the ``py3-none-any`` tag.

The staging sources are committed in git and shipped inside the sdist via
``[[tool.poetry.include]]``. Staging is a graceful no-op when they are absent
(e.g. the Docker builder runs ``uv sync`` before ``dist/`` is copied in and
mounts specs from ``dist/openapi/`` at runtime instead); the release
workflow's ``--check`` pre-flight remains the hard gate for published
artifacts.

Stdlib-only apart from poetry-core (the sole build requirement).
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from poetry.core.masonry.api import (  # noqa: F401  (re-exported PEP 517 hooks)
    build_sdist,
    get_requires_for_build_sdist,
    get_requires_for_build_wheel,
    prepare_metadata_for_build_wheel,
)
from poetry.core.masonry.api import build_editable as _build_editable
from poetry.core.masonry.api import build_wheel as _build_wheel

try:  # optional PEP 660 hooks, present on current poetry-core
    from poetry.core.masonry.api import (  # noqa: F401
        get_requires_for_build_editable,
        prepare_metadata_for_build_editable,
    )
except ImportError:  # pragma: no cover
    pass

_ROOT = Path(__file__).resolve().parent
_STAGER = _ROOT / "src" / "amazon_ads_mcp" / "build" / "stage_wheel_resources.py"


def _stage_resources() -> None:
    if not _STAGER.is_file():
        # The sdist includes the stager; a tree without it can only be a
        # hand-pruned checkout. Staged files may already be present, so
        # warn instead of failing the build.
        print(
            f"[build_package] stager not found at {_STAGER}; "
            "skipping resource staging.",
            file=sys.stderr,
        )
        return
    spec = importlib.util.spec_from_file_location(
        "stage_wheel_resources", _STAGER
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.stage(
        resources_src=_ROOT / "dist" / "openapi" / "resources",
        overlays_src=_ROOT / "dist" / "openapi" / "overlays",
        dest=_ROOT / "src" / "amazon_ads_mcp" / "resources",
    )


def build_wheel(
    wheel_directory, config_settings=None, metadata_directory=None
):
    _stage_resources()
    return _build_wheel(wheel_directory, config_settings, metadata_directory)


def build_editable(
    wheel_directory, config_settings=None, metadata_directory=None
):
    _stage_resources()
    return _build_editable(
        wheel_directory, config_settings, metadata_directory
    )
