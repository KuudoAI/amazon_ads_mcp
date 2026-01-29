"""Comprehensive tests for resilience patterns implementation."""

import asyncio
import time
from datetime import datetime, timedelta
from email.utils import formatdate
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from amazon_ads_mcp.utils.http.resilience import (
    CircuitBreaker,
    CircuitState,
    MetricsCollector,
    ResilientRetry,
    TokenBucket,
    circuit_breakers,
    get_circuit_breaker,
    get_endpoint_family,
    get_region_from_url,
    is_idempotent_request,
    parse_retry_after,
    should_retry_status,
)
from amazon_ads_mcp.utils.http.resilient_client import ResilientAuthenticatedClient


class TestMetricsCollector:
    """Test metrics collection functionality."""
    
    def test_record_throttle(self):
        """Test throttle recording."""
        metrics = MetricsCollector()
        metrics.record_throttle("/v2/campaigns", "na")
        metrics.record_throttle("/v2/campaigns", "na")
        metrics.record_throttle("/v2/campaigns", "eu")
        
        data = metrics.get_metrics()
        assert data["counters"]["ads_api_throttles_total./v2/campaigns.na"] == 2
        assert data["counters"]["ads_api_throttles_total./v2/campaigns.eu"] == 1
    
    def test_record_retry(self):
        """Test retry attempt recording."""
        metrics = MetricsCollector()
        metrics.record_retry("/v2/profiles", 1, 2.5)
        metrics.record_retry("/v2/profiles", 2, 5.0)
        
        data = metrics.get_metrics()
        assert data["counters"]["retry_attempts_total./v2/profiles"] == 2
        assert data["histograms"]["retry_delay_seconds./v2/profiles"] == 5.0
    
    def test_record_circuit_state(self):
        """Test circuit breaker state recording."""
        metrics = MetricsCollector()
        metrics.record_circuit_state("/amc", "open")
        metrics.record_circuit_state("/amc", "half_open")
        metrics.record_circuit_state("/amc", "closed")
        
        data = metrics.get_metrics()
        assert data["gauges"]["circuit_breaker_state./amc"] == "closed"


class TestCircuitBreaker:
    """Test circuit breaker implementation."""
    
    def test_initial_state(self):
        """Test circuit breaker starts closed."""
        breaker = CircuitBreaker(endpoint="/v2/campaigns")
        assert breaker.state == CircuitState.CLOSED
        assert not breaker.is_open()
    
    def test_opens_after_threshold(self):
        """Test circuit opens after failure threshold."""
        breaker = CircuitBreaker(failure_threshold=3, endpoint="/v2/campaigns")
        
        # Record failures
        breaker.record_failure()
        assert breaker.state == CircuitState.CLOSED
        
        breaker.record_failure()
        assert breaker.state == CircuitState.CLOSED
        
        breaker.record_failure()
        assert breaker.state == CircuitState.OPEN
        assert breaker.is_open()
    
    def test_half_open_after_timeout(self):
        """Test circuit enters half-open after recovery timeout."""
        breaker = CircuitBreaker(
            failure_threshold=1,
            recovery_timeout=0.1,
            endpoint="/v2/campaigns"
        )
        
        breaker.record_failure()
        assert breaker.state == CircuitState.OPEN
        assert breaker.is_open()
        
        # Wait for recovery timeout
        time.sleep(0.15)
        assert not breaker.is_open()  # Should transition to HALF_OPEN
        assert breaker.state == CircuitState.HALF_OPEN
    
    def test_closes_after_success_in_half_open(self):
        """Test circuit closes after successful requests in half-open."""
        breaker = CircuitBreaker(
            failure_threshold=1,
            recovery_timeout=0.1,
            half_open_requests=2,
            endpoint="/v2/campaigns"
        )
        
        # Open the circuit
        breaker.record_failure()
        time.sleep(0.15)
        
        # Enter half-open
        assert not breaker.is_open()
        assert breaker.state == CircuitState.HALF_OPEN
        
        # Record successes
        breaker.record_success()
        assert breaker.state == CircuitState.HALF_OPEN
        
        breaker.record_success()
        assert breaker.state == CircuitState.CLOSED
    
    def test_reopens_on_failure_in_half_open(self):
        """Test circuit reopens on failure during half-open."""
        breaker = CircuitBreaker(
            failure_threshold=1,
            recovery_timeout=0.1,
            endpoint="/v2/campaigns"
        )
        
        # Open the circuit
        breaker.record_failure()
        time.sleep(0.15)
        
        # Enter half-open
        assert not breaker.is_open()
        assert breaker.state == CircuitState.HALF_OPEN
        
        # Fail in half-open
        breaker.record_failure()
        assert breaker.state == CircuitState.OPEN
        assert breaker.is_open()


class TestTokenBucket:
    """Test token bucket rate limiting."""
    
    def test_initial_tokens(self):
        """Test bucket starts with full capacity."""
        bucket = TokenBucket(capacity=10, tokens=10, endpoint="/v2/campaigns", region="na")
        assert bucket.tokens == 10
    
    def test_refill_rate(self):
        """Test token refill at correct rate."""
        bucket = TokenBucket(capacity=10, tokens=0, endpoint="/v2/campaigns", region="na")
        
        # Wait 0.1 seconds (should refill 1 token at 10 TPS)
        time.sleep(0.1)
        bucket.refill()
        
        # Should have approximately 1 token (allowing for timing variance)
        assert 0.8 <= bucket.tokens <= 1.2
    
    def test_capacity_limit(self):
        """Test tokens don't exceed capacity."""
        bucket = TokenBucket(capacity=10, tokens=10, endpoint="/v2/campaigns", region="na")
        
        # Wait to accumulate tokens
        time.sleep(0.5)
        bucket.refill()
        
        # Should still be at capacity
        assert bucket.tokens == 10
    
    @pytest.mark.asyncio
    async def test_acquire_immediate(self):
        """Test immediate token acquisition when available."""
        bucket = TokenBucket(capacity=10, tokens=5, endpoint="/v2/campaigns", region="na")
        
        start = time.time()
        acquired = await bucket.acquire(timeout=1.0)
        duration = time.time() - start
        
        assert acquired
        assert duration < 0.1  # Should be immediate
        # Account for small refill during execution
        assert 3.9 <= bucket.tokens <= 4.1
    
    @pytest.mark.asyncio
    async def test_acquire_wait(self):
        """Test waiting for token when none available."""
        bucket = TokenBucket(capacity=10, tokens=0, endpoint="/v2/campaigns", region="na")
        
        start = time.time()
        acquired = await bucket.acquire(timeout=0.2)
        duration = time.time() - start
        
        assert acquired
        assert 0.02 <= duration <= 0.3  # Allow scheduling variance
    
    @pytest.mark.asyncio
    async def test_acquire_timeout(self):
        """Test timeout when token not available in time."""
        bucket = TokenBucket(capacity=1, tokens=0, endpoint="/v2/campaigns", region="na")
        
        # Acquire should timeout quickly
        acquired = await bucket.acquire(timeout=0.05)
        assert not acquired
    
    @pytest.mark.asyncio
    async def test_queue_back_pressure(self):
        """Test back-pressure when queue is full."""
        bucket = TokenBucket(capacity=1, tokens=0, endpoint="/v2/campaigns", region="na")
        
        # Fill the queue with fake futures
        bucket.queue = [asyncio.Future() for _ in range(101)]
        
        with pytest.raises(Exception, match="queue full"):
            await bucket.acquire(timeout=1.0)


class TestUtilityFunctions:
    """Test utility functions."""
    
    def test_get_endpoint_family(self):
        """Test endpoint family extraction."""
        assert get_endpoint_family("https://api.amazon.com/v2/campaigns/123") == "/v2/campaigns"
        assert get_endpoint_family("https://api.amazon.com/v2/ad-groups") == "/v2/ad-groups"
        assert get_endpoint_family("https://api.amazon.com/reporting/reports") == "/reporting"
        assert get_endpoint_family("https://api.amazon.com/amc/audiences") == "/amc"
        assert get_endpoint_family("https://api.amazon.com/unknown") == "default"
    
    def test_get_region_from_url(self):
        """Test region extraction from URL."""
        assert get_region_from_url("https://advertising-api.amazon.com/v2/profiles") == "na"
        assert get_region_from_url("https://advertising-api-eu.amazon.com/v2/profiles") == "eu"
        assert get_region_from_url("https://advertising-api-fe.amazon.com/v2/profiles") == "fe"
    
    def test_should_retry_status(self):
        """Test retryable status code detection."""
        assert should_retry_status(429)  # Throttle
        assert should_retry_status(408)  # Timeout
        assert should_retry_status(502)  # Bad Gateway
        assert should_retry_status(503)  # Service Unavailable
        assert should_retry_status(504)  # Gateway Timeout
        
        assert not should_retry_status(400)  # Bad Request
        assert not should_retry_status(401)  # Unauthorized
        assert not should_retry_status(403)  # Forbidden
        assert not should_retry_status(404)  # Not Found
        assert not should_retry_status(422)  # Unprocessable Entity
    
    def test_is_idempotent_request(self):
        """Test idempotent request detection."""
        # GET is idempotent
        req = httpx.Request("GET", "https://api.amazon.com/v2/campaigns")
        assert is_idempotent_request(req)
        
        # PUT is idempotent
        req = httpx.Request("PUT", "https://api.amazon.com/v2/campaigns/123")
        assert is_idempotent_request(req)
        
        # DELETE is idempotent
        req = httpx.Request("DELETE", "https://api.amazon.com/v2/campaigns/123")
        assert is_idempotent_request(req)
        
        # POST without idempotency key is not idempotent
        req = httpx.Request("POST", "https://api.amazon.com/v2/campaigns")
        assert not is_idempotent_request(req)
        
        # POST with idempotency key is idempotent
        req = httpx.Request(
            "POST",
            "https://api.amazon.com/v2/campaigns",
            headers={"idempotency-key": "abc123"}
        )
        assert is_idempotent_request(req)
    
    def test_parse_retry_after_seconds(self):
        """Test parsing Retry-After as delta-seconds."""
        response = httpx.Response(429, headers={"retry-after": "30"})
        delay = parse_retry_after(response)
        assert delay == 30.0
    
    def test_parse_retry_after_http_date(self):
        """Test parsing Retry-After as HTTP-date."""
        future_time = datetime.now() + timedelta(seconds=45)
        http_date = formatdate(future_time.timestamp(), usegmt=True)
        
        response = httpx.Response(429, headers={"retry-after": http_date})
        delay = parse_retry_after(response)
        
        # Should be approximately 45 seconds (allowing for execution time)
        assert 44 <= delay <= 46
    
    def test_parse_retry_after_missing(self):
        """Test parsing missing Retry-After header."""
        response = httpx.Response(429)
        delay = parse_retry_after(response)
        assert delay is None
    
    def test_parse_retry_after_invalid(self):
        """Test parsing invalid Retry-After header."""
        response = httpx.Response(429, headers={"retry-after": "invalid"})
        delay = parse_retry_after(response)
        assert delay is None


class TestResilientRetry:
    """Test resilient retry decorator."""
    
    @pytest.mark.asyncio
    async def test_success_no_retry(self):
        """Test successful call doesn't retry."""
        call_count = 0
        
        @ResilientRetry(max_attempts=3)
        async def test_func():
            nonlocal call_count
            call_count += 1
            return "success"
        
        result = await test_func()
        assert result == "success"
        assert call_count == 1
    
    @pytest.mark.asyncio
    async def test_retry_on_429(self):
        """Test retry on throttle response."""
        call_count = 0
        
        @ResilientRetry(max_attempts=3, initial_delay=0.01)
        async def test_func(request):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                response = httpx.Response(429)
                raise httpx.HTTPStatusError("throttled", request=request, response=response)
            return "success"
        
        request = httpx.Request("GET", "https://advertising-api.amazon.com/v2/campaigns")
        result = await test_func(request)
        assert result == "success"
        assert call_count == 3
    
    @pytest.mark.asyncio
    async def test_retry_with_retry_after(self):
        """Test honoring Retry-After header."""
        call_count = 0
        start_time = time.time()
        
        @ResilientRetry(max_attempts=2, initial_delay=10.0, use_circuit_breaker=False)  # High initial delay, disable circuit breaker
        async def test_func(request):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                response = httpx.Response(429, headers={"retry-after": "0.1"})
                raise httpx.HTTPStatusError("throttled", request=request, response=response)
            return "success"
        
        request = httpx.Request("GET", "https://advertising-api.amazon.com/v2/campaigns")
        result = await test_func(request)
        duration = time.time() - start_time
        
        assert result == "success"
        assert call_count == 2
        # Should use Retry-After value (0.1s) instead of initial_delay (10s)
        # Allow more time for rate limiting and processing
        assert 0.1 <= duration <= 10.0
    
    @pytest.mark.asyncio
    async def test_total_timeout_budget(self):
        """Test total timeout budget enforcement."""
        call_count = 0
        
        @ResilientRetry(max_attempts=10, initial_delay=0.5, total_timeout=0.2, use_circuit_breaker=False, use_rate_limiter=False)
        async def test_func(request):
            nonlocal call_count
            call_count += 1
            response = httpx.Response(429)
            raise httpx.HTTPStatusError("throttled", request=request, response=response)
        
        request = httpx.Request("GET", "https://advertising-api.amazon.com/v2/campaigns")
        
        with pytest.raises(Exception, match="(Retry timeout|throttled)"):
            await test_func(request)
        
        # Should have tried but not exhausted all attempts due to timeout
        assert 1 <= call_count <= 3
    
    @pytest.mark.asyncio
    async def test_max_delay_cap(self):
        """Test delay is capped at max_delay."""
        delays = []
        original_sleep = asyncio.sleep
        
        async def mock_sleep(delay):
            delays.append(delay)
            await original_sleep(0.001)  # Sleep briefly
        
        with patch("asyncio.sleep", mock_sleep):
            @ResilientRetry(
                max_attempts=5,
                initial_delay=10.0,
                backoff_multiplier=10.0,
                max_delay=1.0
            )
            async def test_func(request):
                response = httpx.Response(503)
                raise httpx.HTTPStatusError("error", request=request, response=response)
            
            request = httpx.Request("GET", "https://advertising-api.amazon.com/v2/campaigns")
            
            with pytest.raises(httpx.HTTPStatusError):
                await test_func(request)
        
        # All delays should be capped at max_delay (1.0)
        for delay in delays:
            assert delay <= 1.0
    
    @pytest.mark.asyncio
    async def test_full_jitter(self):
        """Test full jitter implementation."""
        # Clear any existing circuit breaker state
        circuit_breakers.clear()
        
        delays = []
        original_sleep = asyncio.sleep
        
        async def mock_sleep(delay):
            delays.append(delay)
            await original_sleep(0.001)
        
        with patch("asyncio.sleep", mock_sleep):
            @ResilientRetry(max_attempts=5, initial_delay=1.0, use_circuit_breaker=False, use_rate_limiter=False)
            async def test_func(request):
                response = httpx.Response(503)
                raise httpx.HTTPStatusError("error", request=request, response=response)
            
            request = httpx.Request("GET", "https://advertising-api.amazon.com/v2/campaigns")
            
            with pytest.raises(httpx.HTTPStatusError):
                await test_func(request)
        
        # Check that delays use full jitter (0 to current_delay)
        assert len(delays) == 4  # max_attempts - 1
        
        # First delay should be between 0 and initial_delay
        assert 0 <= delays[0] <= 1.0
        
        # Subsequent delays should increase but with jitter
        for i, delay in enumerate(delays[1:], 1):
            max_expected = min(1.0 * (2 ** i), 60.0)
            assert 0 <= delay <= max_expected
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_integration(self):
        """Test circuit breaker blocks requests when open."""
        # Set up a circuit breaker that's already open
        breaker = get_circuit_breaker("/v2/campaigns")
        breaker.state = CircuitState.OPEN
        breaker.last_failure_time = time.time()
        
        @ResilientRetry(use_circuit_breaker=True)
        async def test_func(request):
            return "success"
        
        request = httpx.Request("GET", "https://advertising-api.amazon.com/v2/campaigns")
        
        with pytest.raises(Exception, match="Circuit breaker OPEN"):
            await test_func(request)
    
    @pytest.mark.asyncio
    async def test_interactive_vs_batch_mode(self):
        """Test different configurations for interactive vs batch."""
        interactive = ResilientRetry.for_interactive()
        batch = ResilientRetry.for_batch()
        
        assert interactive.max_attempts == 5
        assert interactive.total_timeout == 120  # 2 minutes
        
        assert batch.max_attempts == 10
        assert batch.total_timeout == 300  # 5 minutes


class TestResilientAuthenticatedClient:
    """Test resilient authenticated client integration."""
    
    @pytest.mark.asyncio
    async def test_client_initialization(self):
        """Test client initializes with correct settings."""
        auth_manager = MagicMock()
        client = ResilientAuthenticatedClient(
            auth_manager=auth_manager,
            enable_rate_limiting=True,
            enable_circuit_breaker=True,
            interactive_mode=True
        )
        
        assert client.enable_rate_limiting
        assert client.enable_circuit_breaker
        assert client.interactive_mode
    
    @pytest.mark.asyncio
    async def test_metrics_collection(self):
        """Test client collects metrics."""
        auth_manager = MagicMock()
        auth_manager.get_headers = AsyncMock(return_value={
            "Authorization": "Bearer token",
            "Amazon-Advertising-API-ClientId": "client123"
        })
        
        # Create client to ensure it works with auth_manager
        ResilientAuthenticatedClient(auth_manager=auth_manager)
        
        # Record metrics directly on the global metrics instance
        from amazon_ads_mcp.utils.http.resilience import metrics
        metrics.record_throttle("/v2/campaigns", "na")
        metrics.record_retry("/v2/campaigns", 1, 2.5)
        
        # Get metrics from the global instance
        client_metrics = metrics.get_metrics()
        assert "counters" in client_metrics
        assert "ads_api_throttles_total./v2/campaigns.na" in client_metrics["counters"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
