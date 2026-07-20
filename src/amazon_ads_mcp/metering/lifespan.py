"""Lifespan wiring: start/stop the metering runtime, and the `/health`
payload merge (Task 22 ruling #8).

Kept separate from `server/mcp_server.py`'s `server_lifespan()` so the
gating/strict-failure logic is unit-testable without a running FastMCP
server (see `tests/metering/test_lifespan.py`). `server_lifespan()` calls
`start_metering()` in its existing startup `try` block (so a raised
exception is already caught, logged, and re-raised by that block's
`except Exception as e: logger.error(...); raise`) and `stop_metering()`
in its `finally` block, BEFORE `http_client_manager.close_all()`.

Billing-critical policy (design §7.3: "startup validates before accepting
traffic"): `METERING_ENABLED` is the master switch.

- Unset, empty, or exactly ``"false"`` (case-insensitive): metering is not
  requested at all -- a silent no-op, the overwhelmingly common case on
  every Python version and in every deployment that hasn't opted in.
- Any OTHER non-empty value ("true", "TRUE", "1", a typo): an ATTEMPT is
  made to start metering, so a genuine misconfiguration is logged loudly
  rather than silently ignored.
- Whether a startup FAILURE (Python<3.12, package unavailable, invalid
  config, etc.) is fatal depends on whether the value is STRICTLY "true"
  (case-insensitive exact match, matching
  `mcp_outbound_metering.policy`'s own `_parse_bool` convention): if
  strict, `start_metering()` re-raises (server refuses to accept traffic
  without metering); otherwise it logs and returns `None` (server
  continues without metering).
"""

from __future__ import annotations

import logging
import os
from typing import Any, Mapping, Optional

from . import compat
from .adapter import get_metering_runtime, set_metering_runtime

logger = logging.getLogger(__name__)

__all__ = ["metering_health_payload", "start_metering", "stop_metering"]

_DEFAULT_CONFIG_PATH = "metering.yaml"


def _is_truthy(raw: Optional[str]) -> bool:
    if raw is None:
        return False
    return raw.strip().lower() not in ("", "false")


def _is_strict(raw: Optional[str]) -> bool:
    return raw is not None and raw.strip().lower() == "true"


async def start_metering(env: Optional[Mapping[str, str]] = None) -> Optional[Any]:
    """Attempt to construct and start the metering runtime per
    ``METERING_ENABLED`` (read from ``env``, defaulting to the real
    process environment). Returns the started runtime (already installed
    via :func:`set_metering_runtime`) or ``None`` when metering was not
    requested, or could not start non-fatally. Raises when
    ``METERING_ENABLED`` is strictly ``"true"`` and startup fails for any
    reason.
    """
    source = env if env is not None else os.environ
    raw = source.get("METERING_ENABLED")

    if not _is_truthy(raw):
        return None

    strict = _is_strict(raw)

    if not compat.METERING_AVAILABLE:
        compat.warn_unsupported()
        if strict:
            raise RuntimeError(
                "METERING_ENABLED=true but metering is unavailable (requires "
                "Python>=3.12 and mcp-outbound-metering installed); refusing "
                "to start without metering (design §7.3)"
            )
        return None

    config_path = source.get("METERING_CONFIG", _DEFAULT_CONFIG_PATH)
    try:
        runtime = compat.MeteringRuntime.from_config(config_path, source)
        await runtime.start()
    except Exception:
        logger.exception(
            "metering startup failed (config=%s, strict=%s)", config_path, strict
        )
        if strict:
            raise
        return None

    set_metering_runtime(runtime)
    logger.info("metering enabled and started (config=%s)", config_path)
    return runtime


async def stop_metering() -> None:
    """Idempotent and safe to call even when metering was never started.
    Clears the module-level runtime accessor FIRST, then closes the
    runtime (ruling #8's ordering) -- both steps happen before the
    caller's own `http_client_manager.close_all()`. Never raises: a
    close failure is logged, not propagated, so metering shutdown can
    never block the rest of graceful shutdown.
    """
    runtime = get_metering_runtime()
    if runtime is None:
        return
    set_metering_runtime(None)
    try:
        await runtime.aclose()
    except Exception:
        logger.exception("metering shutdown failed")


def metering_health_payload() -> Optional[dict]:
    """``runtime.health()`` when a runtime is active, else ``None`` --
    merged into the server's ``/health`` payload under ``"metering"``
    (`ServerBuilder._setup_health_check`)."""
    runtime = get_metering_runtime()
    if runtime is None:
        return None
    try:
        return runtime.health()
    except Exception:
        logger.exception("metering health check failed")
        return {"status": "error"}
