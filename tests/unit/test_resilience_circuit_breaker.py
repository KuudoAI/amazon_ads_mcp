"""Verify circuit-breaker accounting is per-logical-request, not per-attempt.

With ``max_attempts=3`` and a failing upstream, the old code called
``record_failure()`` inside each retry's except block. A single logical
request therefore counted as 3 failures against the breaker, and a
single bad minute could trip the breaker for an entire endpoint family.

After the fix we expect exactly one breaker failure per call even when
internal retries exhaust.
"""

from __future__ import annotations

import httpx
import pytest

from amazon_ads_mcp.utils.http import resilience
from amazon_ads_mcp.utils.http.resilience import (
    CircuitBreaker,
    ResilientRetry,
    get_circuit_breaker,
)


@pytest.mark.asyncio
async def test_single_failure_per_logical_request(monkeypatch):
    endpoint = "test-endpoint-singlecall"
    # Start with a clean breaker.
    resilience.circuit_breakers[endpoint] = CircuitBreaker(endpoint=endpoint)

    # Pin get_endpoint_family so every request maps to our endpoint.
    monkeypatch.setattr(
        resilience, "get_endpoint_family", lambda _url: endpoint
    )
    # Short-circuit rate limiter and sleep to keep the test fast.
    monkeypatch.setattr(
        resilience, "get_token_bucket", lambda _url: _AlwaysAcquire()
    )

    async def _instant_sleep(_delay: float) -> None:
        return None

    monkeypatch.setattr(resilience.asyncio, "sleep", _instant_sleep)

    retry = ResilientRetry(
        max_attempts=3,
        initial_delay=0.001,
        max_delay=0.01,
        total_timeout=10.0,
        use_circuit_breaker=True,
        use_rate_limiter=False,
    )

    @retry
    async def failing(request: httpx.Request) -> httpx.Response:
        response = httpx.Response(503, request=request)
        raise httpx.HTTPStatusError("boom", request=request, response=response)

    request = httpx.Request("GET", "https://example.invalid/resource")

    with pytest.raises(httpx.HTTPStatusError):
        await failing(request)

    breaker = get_circuit_breaker(endpoint)
    assert breaker.failure_count == 1, (
        f"expected exactly one breaker failure per logical request, "
        f"got {breaker.failure_count}"
    )


class _AlwaysAcquire:
    async def acquire(self, timeout: float | None = None) -> bool:  # noqa: ARG002
        return True
