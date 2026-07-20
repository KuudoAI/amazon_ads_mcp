"""<3.12 compatibility guard for the metering integration (Task 22 ruling #2).

``mcp-outbound-metering`` requires Python>=3.12 (see its own
``pyproject.toml``), while this repository's floor is 3.10 (CI matrix
3.10-3.12). The dependency itself is therefore declared conditionally
(``pyproject.toml``: ``mcp-outbound-metering[verify] ; python_version >=
'3.12'``) -- on 3.10/3.11 it is simply never installed.

Every other module under ``amazon_ads_mcp.metering`` that needs a real
``mcp_outbound_metering`` symbol imports it from HERE, never directly --
so a <3.12 interpreter (or one where the package failed to install for any
other reason) never even attempts the import. On <3.12 or import failure,
metering support is a loud no-op: :data:`METERING_AVAILABLE` is ``False``,
every re-exported symbol is ``None``, and the rest of the server behaves
exactly as it did before this integration existed. This module itself must
ALWAYS be importable, on every supported Python version -- that is the
entire point of the guard.
"""

from __future__ import annotations

import logging
import sys
from typing import Any, Optional

logger = logging.getLogger(__name__)

__all__ = [
    "METERING_AVAILABLE",
    "METERING_MIN_PYTHON",
    "MeteringConfigError",
    "MeteringError",
    "MeteringRuntime",
    "warn_unsupported",
]

# mcp-outbound-metering's own floor (packages/python/mcp_outbound_metering/
# pyproject.toml: requires-python = ">=3.12").
METERING_MIN_PYTHON = (3, 12)

METERING_AVAILABLE: bool
MeteringRuntime: Optional[Any] = None
MeteringConfigError: Optional[Any] = None
MeteringError: Optional[Any] = None

if sys.version_info >= METERING_MIN_PYTHON:
    try:
        from mcp_outbound_metering.errors import (
            MeteringConfigError as _MeteringConfigError,
        )
        from mcp_outbound_metering.errors import MeteringError as _MeteringError
        from mcp_outbound_metering.runtime import MeteringRuntime as _MeteringRuntime
    except ImportError:
        METERING_AVAILABLE = False
    else:
        METERING_AVAILABLE = True
        MeteringRuntime = _MeteringRuntime
        MeteringConfigError = _MeteringConfigError
        MeteringError = _MeteringError
else:
    METERING_AVAILABLE = False


def warn_unsupported() -> None:
    """Log the loud no-op warning (ruling #2). Callers (the lifespan
    wiring in ``metering.lifespan``) invoke this only when
    ``METERING_ENABLED`` is truthy but :data:`METERING_AVAILABLE` is
    ``False`` -- an unset/false ``METERING_ENABLED`` never logs anything,
    since that is ordinary, expected "metering not configured" behavior on
    any Python version.
    """
    running = ".".join(str(part) for part in sys.version_info[:3])
    logger.warning(
        "metering disabled: requires Python>=%s (running %s) or "
        "mcp-outbound-metering is not installed -- METERING_ENABLED is set "
        "but no usage events will be recorded",
        ".".join(str(p) for p in METERING_MIN_PYTHON),
        running,
    )
