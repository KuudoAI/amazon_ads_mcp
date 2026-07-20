"""Unit tests for metering/lifespan.py (Task 22 ruling #8): the
gate/strict-failure logic behind `server_lifespan()`'s metering
start/stop, tested without spinning up a full FastMCP server.

Billing-critical rule under test: METERING_ENABLED=true (strictly) that
fails to start metering must FAIL server startup, never silently continue
without metering. A looser "truthy" value (attempted but not exactly
"true") degrades non-fatally on failure.
"""

from __future__ import annotations

import asyncio
import sys

import pytest

pytestmark = pytest.mark.skipif(
    sys.version_info < (3, 12), reason="metering requires Python>=3.12"
)

if sys.version_info >= (3, 12):
    from amazon_ads_mcp.metering import lifespan as metering_lifespan
    from amazon_ads_mcp.metering.adapter import get_metering_runtime, set_metering_runtime

    from ._support import CONFIG_PATH, base_env


@pytest.fixture(autouse=True)
def _reset_runtime():
    assert get_metering_runtime() is None
    yield
    set_metering_runtime(None)


def test_unset_metering_enabled_is_a_silent_no_op() -> None:
    async def scenario():
        return await metering_lifespan.start_metering(env={})

    result = asyncio.run(scenario())
    assert result is None
    assert get_metering_runtime() is None


def test_false_metering_enabled_is_a_silent_no_op() -> None:
    async def scenario():
        return await metering_lifespan.start_metering(env={"METERING_ENABLED": "false"})

    result = asyncio.run(scenario())
    assert result is None
    assert get_metering_runtime() is None


def test_strictly_true_and_available_starts_and_installs_runtime(tmp_path) -> None:
    env = base_env(tmp_path)
    env["METERING_CONFIG"] = str(CONFIG_PATH)

    async def scenario():
        runtime = await metering_lifespan.start_metering(env=env)
        assert runtime is get_metering_runtime()
        await metering_lifespan.stop_metering()
        return runtime

    runtime = asyncio.run(scenario())
    assert runtime is not None
    assert get_metering_runtime() is None  # cleared by stop_metering


def test_strictly_true_with_malformed_config_fails_startup(tmp_path) -> None:
    """Billing-critical: METERING_ENABLED=true (strict) + a startup
    failure (here: a missing/invalid config file) must RAISE, not
    silently continue without metering."""
    env = {"METERING_ENABLED": "true", "METERING_CONFIG": str(tmp_path / "does-not-exist.yaml")}

    async def scenario():
        await metering_lifespan.start_metering(env=env)

    with pytest.raises(Exception):
        asyncio.run(scenario())
    assert get_metering_runtime() is None


def test_loosely_truthy_but_not_strict_degrades_non_fatally_on_failure(tmp_path) -> None:
    """METERING_ENABLED=1 is truthy enough to ATTEMPT startup (so a
    genuine misconfiguration gets logged, not silently ignored) but is
    not the strict "true" the billing-critical rule requires -- a
    failure here must NOT raise."""
    env = {"METERING_ENABLED": "1", "METERING_CONFIG": str(tmp_path / "does-not-exist.yaml")}

    async def scenario():
        return await metering_lifespan.start_metering(env=env)

    result = asyncio.run(scenario())
    assert result is None
    assert get_metering_runtime() is None


def test_stop_metering_is_idempotent_and_safe_when_never_started() -> None:
    async def scenario():
        await metering_lifespan.stop_metering()
        await metering_lifespan.stop_metering()

    asyncio.run(scenario())  # must not raise
    assert get_metering_runtime() is None


def test_health_payload_none_when_no_active_runtime() -> None:
    assert metering_lifespan.metering_health_payload() is None


def test_health_payload_reflects_active_runtime(tmp_path) -> None:
    env = base_env(tmp_path)
    env["METERING_CONFIG"] = str(CONFIG_PATH)

    async def scenario():
        await metering_lifespan.start_metering(env=env)
        payload = metering_lifespan.metering_health_payload()
        await metering_lifespan.stop_metering()
        return payload

    payload = asyncio.run(scenario())
    assert payload is not None
    assert payload["status"] in ("healthy", "degraded", "unhealthy")
