"""Conformance harness factory (Task 22 ruling #8) -- the scaffold's
generated harness factory, adapted into this repo's real modules.

Two things drive this module:

1. ``tests/metering/test_conformance.py`` (``ProducerConformanceSuite``
   subclass, zero overrides) -- ``uv run pytest tests/metering -q``.
2. ``mcp-metering verify --config metering.yaml --harness
   amazon_ads_mcp.metering.conformance:create_conformance_harness`` --
   the CI ``metering`` job (ruling #9).

Both require the integration guide's §4 CI environment block to already
be exported in the real process environment (this module reads
``os.environ`` directly, like the scaffold's own template -- it does not
hardcode conformance-only values the way ``examples/httpx`` does, since
this is the real adapter a real deployment also loads through
``metering.lifespan.start_metering()``). ``tests/metering/conftest.py``
exports that same block via ``monkeypatch`` so the pytest path is
self-sufficient locally too.

Builds the REAL ``AuthenticatedClient`` construction path (design
§3.5.5): ``make_provider_client`` constructs an actual
``AuthenticatedClient`` after ``set_metering_runtime`` has installed this
harness's runtime, so ``AuthenticatedClient.__init__``'s own
``install_metered_transport`` call (``utils/http_client.py``) is what
wraps the transport here -- never a direct call to
``runtime.wrap_transport`` from this module.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Optional

import httpx

from . import compat
from .adapter import set_metering_runtime

__all__ = ["create_conformance_harness"]

_REPO_ROOT = Path(__file__).resolve().parents[3]
_CONFIG_PATH = _REPO_ROOT / "metering.yaml"

_EXPECTED_DIMENSIONS = frozenset({"identity_id", "profile_id", "region", "auth_method", "tool_name"})


class _ConformanceAuthManager:
    """Minimal `AuthenticatedClient`-compatible auth manager: enough for
    `_inject_headers` to succeed (a valid Authorization + ClientId pair)
    without a real provider, credential store, or network endpoint.
    `provider = None` keeps the identity-routing branch off, so requests
    are never rewritten away from whatever host the suite's upstream
    double is registered under."""

    provider = None

    async def get_headers(self) -> Dict[str, str]:
        return {
            "Authorization": "Bearer conformance-test-token",
            "Amazon-Advertising-API-ClientId": "conformance-test-client-id",
        }


class _RaisingTelemetryMirror:
    """A `TelemetryMirror` that violates its own never-raise contract on
    purpose -- installed only when `options.break_mirror` is `True`
    (`ProducerConformanceSuite`'s mirror-isolation scenario)."""

    def __init__(self) -> None:
        self.failure_count = 0

    def emit_usage_event(self, event: Dict[str, Any]) -> None:
        self.failure_count += 1
        raise RuntimeError("mcp-metering conformance: mirror double violates its contract on purpose")

    def close(self) -> None:
        return None


class _Harness:
    """The `ConformanceHarness` this module exposes -- matches the
    `Protocol` in `mcp_outbound_metering.conformance.harness`
    structurally, no inheritance needed."""

    def __init__(self, runtime: Any) -> None:
        self.runtime = runtime
        self.allowed_host = os.environ.get("METERING_UPSTREAM_HOSTS", "").split(",")[0]
        self.disallowed_lookalike_host = f"{self.allowed_host}.evil.invalid"
        self.expected_dimensions = _EXPECTED_DIMENSIONS

    async def make_provider_client(self, upstream: httpx.AsyncBaseTransport) -> httpx.AsyncClient:
        """The REAL construction path: `AuthenticatedClient.__init__`
        (`utils/http_client.py`) calls `install_metered_transport`,
        which reads the module-level runtime `create_conformance_harness`
        already installed via `set_metering_runtime`."""
        from ..utils.http_client import AuthenticatedClient

        return AuthenticatedClient(transport=upstream, auth_manager=_ConformanceAuthManager())

    async def invoke_internal_only(self) -> None:
        """One representative internal/excluded operation: constructing
        (and closing) a plain `httpx.AsyncClient` -- the exact shape
        every OAuth/OpenBridge/Kuudo provider client takes in this repo
        (verified repo fact) -- which structurally never touches the
        metered transport regardless of whether a runtime is active."""
        client = httpx.AsyncClient()
        await client.aclose()

    async def aclose(self) -> None:
        set_metering_runtime(None)
        await self.runtime.aclose()


def _env(path: Path) -> Dict[str, str]:
    """Environment overlay for `MeteringRuntime.from_config`, read from
    the REAL process environment -- no value is ever hardcoded here
    (design §3.3: "never writes secrets into tracked files"). The
    integration guide's §4 CI environment block supplies every
    `METERING_*` value this needs when running `mcp-metering verify` or
    `pytest tests/metering`; only per-source-id/per-instance defaults are
    filled in here via `setdefault`."""
    overlay = dict(os.environ)
    overlay.setdefault("METERING_SOURCE_ID", "amazon_ads_mcp")
    overlay.setdefault("METERING_UPSTREAM_SERVICE", "amazon_ads")
    overlay.setdefault("METERING_OUTBOX_PATH", str(path / "outbox.db"))
    overlay.setdefault(
        "METERING_DIMENSIONS", ",".join(sorted(_EXPECTED_DIMENSIONS))
    )
    return overlay


async def create_conformance_harness(path: Path, options: Any) -> Any:
    """Factory for `mcp_outbound_metering.conformance.ProducerConformanceSuite`
    (design §3.5.5), wired the SAME way `metering.lifespan.start_metering`
    constructs the runtime in production
    (`MeteringRuntime.from_config` -> `await start()` ->
    `set_metering_runtime`). `options` is a
    `mcp_outbound_metering.conformance.HarnessOptions` -- typed `Any` here
    so importing this module never requires metering to be available at
    import time, only when this factory actually runs.
    """
    if not compat.METERING_AVAILABLE:
        raise RuntimeError(
            "metering conformance harness requires Python>=3.12 and "
            "mcp-outbound-metering installed"
        )

    env = _env(path)
    env.update(options.env_overrides)

    exporter_transport = options.ingest_transport
    if exporter_transport is None:
        # A safe, non-networked default -- never fall back to a real
        # network call here.
        exporter_transport = httpx.MockTransport(lambda request: httpx.Response(200))

    mirror: Optional[Any] = _RaisingTelemetryMirror() if options.break_mirror else None

    runtime = compat.MeteringRuntime.from_config(
        _CONFIG_PATH,
        env,
        exporter_transport=exporter_transport,
        mirror=mirror,
        flusher_now=options.flusher_now,
        flusher_sleep=options.flusher_sleep,
    )
    await runtime.start()
    set_metering_runtime(runtime)

    return _Harness(runtime)
