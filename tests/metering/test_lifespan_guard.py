"""Billing-critical guard test (Task 22 ruling #2 + #8): strict
METERING_ENABLED=true FAILS server startup on an interpreter where
metering is unavailable (<3.12, or a failed import) -- it must never
silently continue without metering.

Not skipif-guarded, same rationale as `test_compat_guard.py`:
`amazon_ads_mcp.metering.lifespan` has no module-level dependency on
`mcp_outbound_metering` (only on `compat`, which is always importable),
so this is the one test file that specifically proves the STRICT-failure
behavior on the repo's 3.10 floor, where `compat.METERING_AVAILABLE` is
naturally `False` -- exactly the scenario the billing-critical rule
exists for. On 3.12 with the package installed, this same assertion is
covered indirectly by `test_lifespan.py`'s malformed-config strict-failure
test (metering IS available there, so unavailability can't be exercised;
this file's `test_strict_enabled_raises_when_metering_unavailable` fills
that gap by simulating unavailability directly).
"""

from __future__ import annotations

import asyncio

import pytest

from amazon_ads_mcp.metering import compat, lifespan
from amazon_ads_mcp.metering.adapter import get_metering_runtime, set_metering_runtime


@pytest.fixture(autouse=True)
def _reset_runtime():
    assert get_metering_runtime() is None
    yield
    set_metering_runtime(None)


def test_strict_enabled_raises_when_metering_unavailable(monkeypatch) -> None:
    monkeypatch.setattr(compat, "METERING_AVAILABLE", False)

    async def scenario():
        await lifespan.start_metering(env={"METERING_ENABLED": "true"})

    with pytest.raises(RuntimeError, match="METERING_ENABLED=true"):
        asyncio.run(scenario())
    assert get_metering_runtime() is None


def test_loosely_enabled_does_not_raise_when_metering_unavailable(monkeypatch, caplog) -> None:
    import logging

    monkeypatch.setattr(compat, "METERING_AVAILABLE", False)

    async def scenario():
        return await lifespan.start_metering(env={"METERING_ENABLED": "1"})

    with caplog.at_level(logging.WARNING):
        result = asyncio.run(scenario())
    assert result is None
    assert get_metering_runtime() is None
    assert any("Python>=3.12" in r.message for r in caplog.records)


def test_unset_never_warns_even_when_metering_unavailable(monkeypatch, caplog) -> None:
    import logging

    monkeypatch.setattr(compat, "METERING_AVAILABLE", False)

    async def scenario():
        return await lifespan.start_metering(env={})

    with caplog.at_level(logging.WARNING):
        result = asyncio.run(scenario())
    assert result is None
    assert not any("Python>=3.12" in r.message for r in caplog.records)
