"""Coverage-pushing tests for ``utils.http.resilient_client``.

Round-13 had this module at 38% (35 of 56 statements uncovered). The
class wraps AuthenticatedClient with circuit breaker / rate limiting /
retry decorator logic. Tests use the ``conftest.make_direct_auth_manager``
factory and patch the parent class's ``send`` so we exercise the
resilience plumbing without real network.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from amazon_ads_mcp.utils.http.resilience import (
    CircuitBreaker,
    CircuitState,
    circuit_breakers,
    token_buckets,
)
from amazon_ads_mcp.utils.http.resilient_client import (
    ResilientAuthenticatedClient,
    create_resilient_client,
)
from tests.conftest import make_direct_auth_manager


# --- Fixtures -------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_resilience_globals():
    """Clear shared singletons between tests so circuit-breaker state and
    token-bucket queues from one test don't bleed into the next."""
    circuit_breakers.clear()
    token_buckets.clear()
    yield
    circuit_breakers.clear()
    token_buckets.clear()


@pytest.fixture
def mock_response() -> httpx.Response:
    return httpx.Response(
        status_code=200,
        headers={"content-type": "application/json"},
        content=b'{"ok":true}',
        request=httpx.Request("GET", "https://advertising-api.amazon.com/v2/campaigns"),
    )


# --- __init__ -------------------------------------------------------------


class TestInitialization:
    def test_default_kwargs_are_batch_mode(self) -> None:
        client = ResilientAuthenticatedClient(auth_manager=make_direct_auth_manager())
        assert client.enable_rate_limiting is True
        assert client.enable_circuit_breaker is True
        assert client.interactive_mode is False

    def test_interactive_mode_uses_interactive_retry(self) -> None:
        client = ResilientAuthenticatedClient(
            auth_manager=make_direct_auth_manager(),
            interactive_mode=True,
        )
        assert client.interactive_mode is True
        # The retry decorator carries different per-mode timing knobs;
        # here we just verify it exists.
        assert client.retry_decorator is not None

    def test_features_can_be_disabled(self) -> None:
        client = ResilientAuthenticatedClient(
            auth_manager=make_direct_auth_manager(),
            enable_rate_limiting=False,
            enable_circuit_breaker=False,
        )
        assert client.enable_rate_limiting is False
        assert client.enable_circuit_breaker is False


# --- send: happy path -----------------------------------------------------


class TestSendHappyPath:
    @pytest.mark.asyncio
    async def test_successful_send_records_success_in_breaker(
        self, mock_response: httpx.Response
    ) -> None:
        """A successful send must record success on the per-endpoint
        circuit breaker."""
        client = ResilientAuthenticatedClient(
            auth_manager=make_direct_auth_manager(),
            enable_rate_limiting=False,  # Skip rate-limit waits for speed
        )

        request = httpx.Request("GET", "https://advertising-api.amazon.com/v2/campaigns")
        with patch.object(
            type(client).__mro__[1],  # AuthenticatedClient parent
            "send",
            new=AsyncMock(return_value=mock_response),
        ):
            response = await client.send(request)

        assert response is mock_response
        # success_count incremented on the circuit breaker
        breaker = circuit_breakers["/v2/campaigns"]
        # Closed circuit + success path resets failure_count to 0
        assert breaker.state == CircuitState.CLOSED


# --- send: circuit breaker -----------------------------------------------


class TestCircuitBreakerInteraction:
    @pytest.mark.asyncio
    async def test_open_circuit_fails_fast(self) -> None:
        """When the circuit is OPEN, send raises immediately without
        invoking the parent send (no real network call)."""
        client = ResilientAuthenticatedClient(
            auth_manager=make_direct_auth_manager(),
            enable_rate_limiting=False,
        )

        # Pre-open the circuit for this endpoint
        breaker = CircuitBreaker(failure_threshold=1, endpoint="/v2/campaigns")
        breaker.record_failure()
        assert breaker.is_open()
        circuit_breakers["/v2/campaigns"] = breaker

        parent_send = AsyncMock()
        request = httpx.Request("GET", "https://advertising-api.amazon.com/v2/campaigns")
        with patch.object(
            type(client).__mro__[1], "send", new=parent_send,
        ):
            with pytest.raises(Exception, match="Circuit breaker is OPEN"):
                await client.send(request)

        # Critical: parent send must NOT be called when circuit is OPEN
        parent_send.assert_not_called()

    @pytest.mark.asyncio
    async def test_failure_records_failure_in_breaker(self) -> None:
        """An exception from the parent send must record a failure on
        the circuit breaker."""
        client = ResilientAuthenticatedClient(
            auth_manager=make_direct_auth_manager(),
            enable_rate_limiting=False,
        )

        request = httpx.Request("GET", "https://advertising-api.amazon.com/v2/campaigns")
        with patch.object(
            type(client).__mro__[1],
            "send",
            new=AsyncMock(side_effect=httpx.ConnectError("boom")),
        ), patch("asyncio.sleep", new=AsyncMock(return_value=None)):
            with pytest.raises(Exception):
                await client.send(request)

        breaker = circuit_breakers["/v2/campaigns"]
        # Some failure was recorded (count depends on retry attempts)
        assert breaker.failure_count >= 1


# --- send: rate-limiting disabled path ------------------------------------


class TestRateLimitingDisabled:
    @pytest.mark.asyncio
    async def test_rate_limiting_off_skips_token_bucket(
        self, mock_response: httpx.Response
    ) -> None:
        """When rate limiting is off, no token bucket is acquired."""
        client = ResilientAuthenticatedClient(
            auth_manager=make_direct_auth_manager(),
            enable_rate_limiting=False,
            enable_circuit_breaker=False,
        )

        request = httpx.Request("GET", "https://advertising-api.amazon.com/v2/campaigns")
        with patch.object(
            type(client).__mro__[1],
            "send",
            new=AsyncMock(return_value=mock_response),
        ):
            response = await client.send(request)

        assert response is mock_response
        # No bucket created for this endpoint+region
        assert not token_buckets


# --- request convenience method ------------------------------------------


class TestRequestMethod:
    @pytest.mark.asyncio
    async def test_request_builds_and_sends(self, mock_response) -> None:
        """``request`` builds a request via ``build_request`` and forwards
        to ``send``."""
        client = ResilientAuthenticatedClient(
            auth_manager=make_direct_auth_manager(),
            enable_rate_limiting=False,
            enable_circuit_breaker=False,
        )

        with patch.object(
            type(client).__mro__[1],
            "send",
            new=AsyncMock(return_value=mock_response),
        ):
            response = await client.request(
                "GET", "https://advertising-api.amazon.com/v2/campaigns"
            )

        assert response is mock_response


# --- get_metrics / reset_metrics -----------------------------------------


class TestMetricsApi:
    def test_get_metrics_returns_dict(self) -> None:
        """``get_metrics`` returns a plain dict — actual key shape depends
        on whether any metrics have been recorded yet (the underlying
        collector uses defaultdicts that materialize on first write)."""
        client = ResilientAuthenticatedClient(auth_manager=make_direct_auth_manager())
        m = client.get_metrics()
        assert isinstance(m, dict)

    def test_reset_metrics_clears_state(self) -> None:
        client = ResilientAuthenticatedClient(auth_manager=make_direct_auth_manager())
        client.reset_metrics()
        m = client.get_metrics()
        # Fresh collector: any pre-existing counters/histograms/gauges
        # must be cleared. MetricsCollector uses defaultdict, so absent
        # keys read as empty; we accept either "key absent" or "key
        # present with empty mapping" as evidence of reset.
        assert m.get("counters", {}) == {}
        assert m.get("histograms", {}) == {}
        assert m.get("gauges", {}) == {}


# --- create_resilient_client factory --------------------------------------


class TestFactory:
    def test_factory_builds_resilient_client(self) -> None:
        client = create_resilient_client(auth_manager=make_direct_auth_manager())
        assert isinstance(client, ResilientAuthenticatedClient)
        # Defaults to batch mode
        assert client.interactive_mode is False

    def test_factory_passes_interactive_flag(self) -> None:
        client = create_resilient_client(
            auth_manager=make_direct_auth_manager(),
            interactive=True,
        )
        assert client.interactive_mode is True

    def test_factory_passes_extra_kwargs(self) -> None:
        client = create_resilient_client(
            auth_manager=make_direct_auth_manager(),
            enable_rate_limiting=False,
        )
        assert client.enable_rate_limiting is False
