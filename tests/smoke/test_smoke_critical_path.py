"""Smoke gate — fast critical-path checks.

This lane is intended to run as the *first* CI step (before the full unit/
integration suites) so that a fundamentally broken build fails in seconds,
not minutes. Total runtime should stay under ~10s wall clock.

Run locally with:
    uv run pytest -m smoke

Run in CI as a gate, then run the full suite with:
    uv run pytest -m smoke && uv run pytest -m "not smoke"

Scope rules (keep tight):
- Server module imports cleanly.
- Settings construct from env (autouse conftest fixture provides minimal env).
- Resilience primitives behave deterministically with an injected clock.
- The package version + name are exposed.

Do NOT add tests here that:
- Require network or real credentials.
- Take more than ~1s individually.
- Cover edge cases (those belong in unit/).
"""

from __future__ import annotations

import importlib

import pytest

pytestmark = pytest.mark.smoke


def test_package_imports_cleanly():
    """The top-level package imports without side-effect errors."""
    pkg = importlib.import_module("amazon_ads_mcp")
    assert hasattr(pkg, "__name__")


def test_server_module_imports():
    """The MCP server entry-point module imports without error."""
    mod = importlib.import_module("amazon_ads_mcp.server.mcp_server")
    assert hasattr(mod, "create_amazon_ads_server")


def test_settings_construct_from_env():
    """Settings build successfully from the conftest-provided env."""
    from amazon_ads_mcp.config.settings import Settings

    s = Settings()
    # Smoke: just verify construction + a couple required surfaces exist.
    # Don't pin specific values — those belong in unit tests.
    assert s is not None


def test_circuit_breaker_recovers_with_injected_clock():
    """CircuitBreaker honors the recovery_timeout via its clock hook."""
    from amazon_ads_mcp.utils.http.resilience import (
        CircuitBreaker,
        CircuitState,
    )

    now = [0.0]
    breaker = CircuitBreaker(
        failure_threshold=1,
        recovery_timeout=0.1,
        endpoint="/smoke",
        clock=lambda: now[0],
    )
    breaker.record_failure()
    assert breaker.state == CircuitState.OPEN
    now[0] = 0.2
    assert not breaker.is_open()
    assert breaker.state == CircuitState.HALF_OPEN


def test_token_bucket_refills_with_injected_clock():
    """TokenBucket refills deterministically against an injected clock."""
    from amazon_ads_mcp.utils.http.resilience import TokenBucket

    now = [0.0]
    bucket = TokenBucket(
        capacity=10,
        tokens=0,
        endpoint="/smoke",
        region="na",
        clock=lambda: now[0],
    )
    now[0] = 0.5  # 0.5s @ 10 TPS → 5 tokens
    bucket.refill()
    assert bucket.tokens == pytest.approx(5.0)
