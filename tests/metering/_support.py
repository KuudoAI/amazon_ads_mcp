"""Shared test support for tests/metering/ (Task 22).

Not a test module itself (leading underscore keeps pytest from collecting
it). Every module importing this one is skipif-guarded to Python>=3.12, so
importing ``mcp_outbound_metering`` directly here -- rather than through
``amazon_ads_mcp.metering.compat`` -- is safe: this module is never
reached on <3.12.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Callable, Mapping, Optional

import httpx
from mcp_outbound_metering.runtime import MeteringRuntime

REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = REPO_ROOT / "metering.yaml"

ALLOWED_HOST = "advertising-api.amazon.com"
DIMENSIONS = "identity_id,profile_id,region,auth_method,tool_name"


def base_env(tmp_path: Path, *, hosts: str = ALLOWED_HOST) -> dict:
    """Conformance-only fake values (never a real credential/endpoint),
    mirroring the guide's §4 CI environment block and
    examples/httpx/example_adapter.py's ``_base_env``."""
    return {
        "METERING_ENABLED": "true",
        "METERING_SOURCE_ID": "amazon_ads_mcp",
        "METERING_ENDPOINT": "https://ingest.example-metering.test/v1/usage/batches",
        "METERING_DEPLOYMENT_ID": "test-deployment",
        "METERING_INSTANCE_ID": "test-instance",
        "METERING_UPSTREAM_SERVICE": "amazon_ads",
        "METERING_UPSTREAM_HOSTS": hosts,
        "METERING_KEY_ID": "test-key-id",
        "METERING_HMAC_SECRET": "test-hmac-secret-not-real",
        "METERING_OUTBOX_MODE": "sqlite",
        "METERING_OUTBOX_PATH": str(tmp_path / "outbox.db"),
        "METERING_OUTBOX_MAX_BYTES": "10000000",
        "METERING_DIMENSIONS": DIMENSIONS,
        "METERING_OTEL_MIRROR": "false",
        "METERING_BATCH_SIZE": "1",
    }


async def build_runtime(
    tmp_path: Path,
    *,
    ingest: Optional[httpx.AsyncBaseTransport] = None,
    env_overrides: Optional[Mapping[str, str]] = None,
    hosts: str = ALLOWED_HOST,
) -> MeteringRuntime:
    """A started `MeteringRuntime` wired to the repo's real metering.yaml,
    over a scripted (never real-network) ingest transport. Caller owns
    `await runtime.aclose()`."""
    env = base_env(tmp_path, hosts=hosts)
    if env_overrides:
        env.update(env_overrides)
    exporter_transport = ingest or httpx.MockTransport(lambda request: httpx.Response(200))
    runtime = MeteringRuntime.from_config(CONFIG_PATH, env, exporter_transport=exporter_transport)
    await runtime.start()
    return runtime


class RecordingIngestTransport(httpx.AsyncBaseTransport):
    """A fake ingest endpoint that records every batch it receives and
    answers `200` by default. Exposes an event-driven wait
    (`wait_for_event_count`) instead of a fixed sleep, mirroring
    `mcp_outbound_metering.conformance.suite`'s own `_RecordingTransport`
    -- the background flusher task delivers batches asynchronously, so
    tests must wait for arrival rather than guess a sleep duration.
    """

    def __init__(
        self, responder: Optional[Callable[[int, httpx.Request], httpx.Response]] = None
    ) -> None:
        self.requests: list[httpx.Request] = []
        self._responder = responder
        self._arrived = asyncio.Event()

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        await request.aread()
        index = len(self.requests)
        self.requests.append(request)
        self._arrived.set()
        if self._responder is not None:
            return self._responder(index, request)
        return httpx.Response(200)

    def events(self) -> list[dict]:
        flat: list[dict] = []
        for request in self.requests:
            flat.extend(json.loads(request.content))
        return flat

    async def wait_for_event_count(self, n: int, *, timeout: float = 5.0) -> list[dict]:
        async def _wait() -> None:
            while len(self.events()) < n:
                self._arrived.clear()
                if len(self.events()) >= n:
                    return
                await self._arrived.wait()

        await asyncio.wait_for(_wait(), timeout=timeout)
        return self.events()


class FakeAuthManager:
    """The smallest `AuthenticatedClient`-compatible auth manager double:
    provides just enough for `_inject_headers` to succeed (a valid
    Authorization + ClientId header pair) without touching any real
    provider, credential store, or network endpoint. `provider=None`
    keeps `_inject_headers`'s identity-routing branch off (`hasattr(None,
    ...)` is False), so requests are never rewritten away from the
    `allowed_host` a test constructed its upstream against.
    """

    provider = None

    async def get_headers(self) -> dict:
        return {
            "Authorization": "Bearer conformance-test-token",
            "Amazon-Advertising-API-ClientId": "conformance-test-client-id",
        }
