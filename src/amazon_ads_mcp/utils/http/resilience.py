"""Enhanced resilience patterns for Amazon Ads API HTTP operations.

This module provides production-ready implementations of resilience patterns
following Amazon's guidance for API interactions:
- Exponential backoff with full jitter
- Retry-After header support
- Token bucket rate limiting
- Circuit breaker integration
- Per-endpoint/region awareness
- Comprehensive metrics

All implementations follow Amazon's recommended defaults and best practices.
"""

import asyncio
import logging
import random
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, Tuple, TypeVar
from urllib.parse import urlparse

import httpx

from ..region_config import RegionConfig

logger = logging.getLogger(__name__)

T = TypeVar("T")


class MetricsCollector:
    """Collects metrics for monitoring and alerting."""

    def __init__(self):
        self._metrics: Dict[str, Dict[str, Any]] = defaultdict(lambda: defaultdict(int))
        self._start_time = time.time()

    def record_throttle(self, endpoint: str, region: str) -> None:
        """Record a 429 throttle response."""
        key = f"ads_api_throttles_total.{endpoint}.{region}"
        self._metrics["counters"][key] += 1
        logger.debug(f"Throttle recorded: {endpoint} in {region}")

    def record_retry(self, endpoint: str, attempt: int, delay: float) -> None:
        """Record a retry attempt."""
        self._metrics["counters"][f"retry_attempts_total.{endpoint}"] += 1
        self._metrics["histograms"][f"retry_delay_seconds.{endpoint}"] = delay
        logger.debug(f"Retry {attempt} for {endpoint} with {delay:.2f}s delay")

    def record_retry_after(self, endpoint: str, delay: float) -> None:
        """Record observed Retry-After header value."""
        self._metrics["gauges"][f"retry_after_seconds.{endpoint}"] = delay
        logger.info(f"Retry-After header: {delay}s for {endpoint}")

    def record_circuit_state(self, endpoint: str, state: str) -> None:
        """Record circuit breaker state change."""
        self._metrics["gauges"][f"circuit_breaker_state.{endpoint}"] = state
        logger.info(f"Circuit breaker {state} for {endpoint}")

    def record_queue_wait(self, endpoint: str, wait_time: float) -> None:
        """Record token bucket queue wait time."""
        self._metrics["histograms"][f"queue_wait_seconds.{endpoint}"] = wait_time
        if wait_time > 5.0:
            logger.warning(f"Long queue wait: {wait_time:.2f}s for {endpoint}")

    def record_success_after_retry(self, endpoint: str, attempts: int) -> None:
        """Record successful completion after retries."""
        self._metrics["counters"][f"success_after_retry.{endpoint}"] += 1
        logger.info(f"Success after {attempts} attempts for {endpoint}")

    def get_metrics(self) -> Dict[str, Dict[str, Any]]:
        """Get all collected metrics."""
        return dict(self._metrics)


# Global metrics instance
metrics = MetricsCollector()


class CircuitState(Enum):
    """Circuit breaker states."""

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass
class CircuitBreaker:
    """Enhanced circuit breaker with metrics and per-endpoint tracking.

    The ``clock`` field is a swappable monotonic-ish time source (defaults to
    ``time.time``). Tests inject a deterministic stub to avoid wallclock
    sleeps; production behavior is unchanged.
    """

    failure_threshold: int = 5
    recovery_timeout: float = 60.0
    half_open_requests: int = 3
    state: CircuitState = CircuitState.CLOSED
    failure_count: int = 0
    success_count: int = 0
    last_failure_time: Optional[float] = None
    endpoint: str = ""
    clock: Callable[[], float] = field(default=time.time, repr=False, compare=False)

    def is_open(self) -> bool:
        """Check if circuit should block requests."""
        if self.state == CircuitState.OPEN:
            # Use explicit None-check; injected clocks may return 0.0 which
            # would otherwise be treated as falsy and skip the recovery path.
            if (
                self.last_failure_time is not None
                and (self.clock() - self.last_failure_time) >= self.recovery_timeout
            ):
                self.state = CircuitState.HALF_OPEN
                self.success_count = 0
                metrics.record_circuit_state(self.endpoint, "half_open")
                logger.info(f"Circuit entering HALF_OPEN for {self.endpoint}")
                return False
            return True
        return False

    def record_success(self) -> None:
        """Record successful request."""
        if self.state == CircuitState.HALF_OPEN:
            self.success_count += 1
            if self.success_count >= self.half_open_requests:
                self.state = CircuitState.CLOSED
                self.failure_count = 0
                metrics.record_circuit_state(self.endpoint, "closed")
                logger.info(f"Circuit CLOSED for {self.endpoint}")
        elif self.state == CircuitState.CLOSED:
            self.failure_count = 0

    def record_failure(self) -> None:
        """Record failed request."""
        self.failure_count += 1
        self.last_failure_time = self.clock()

        if self.state == CircuitState.HALF_OPEN:
            self.state = CircuitState.OPEN
            metrics.record_circuit_state(self.endpoint, "open")
            logger.warning(f"Circuit OPEN for {self.endpoint} (failed in HALF_OPEN)")
        elif self.failure_count >= self.failure_threshold:
            self.state = CircuitState.OPEN
            metrics.record_circuit_state(self.endpoint, "open")
            logger.warning(f"Circuit OPEN for {self.endpoint} (threshold reached)")


# Per-endpoint circuit breakers
circuit_breakers: Dict[str, CircuitBreaker] = {}


def get_circuit_breaker(endpoint: str) -> CircuitBreaker:
    """Get or create circuit breaker for endpoint."""
    if endpoint not in circuit_breakers:
        circuit_breakers[endpoint] = CircuitBreaker(endpoint=endpoint)
    return circuit_breakers[endpoint]


@dataclass
class TokenBucket:
    """Token bucket for rate limiting with per-endpoint TPS.

    The ``clock`` field defaults to ``time.time`` for production parity. Tests
    inject a deterministic stub to drive ``refill`` and ``acquire`` without
    real sleeps.
    """

    capacity: float  # TPS for this endpoint
    tokens: float
    last_refill: Optional[float] = None
    queue: List[asyncio.Future] = field(default_factory=list)
    endpoint: str = ""
    region: str = ""
    clock: Callable[[], float] = field(default=time.time, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.last_refill is None:
            self.last_refill = self.clock()

    def refill(self) -> None:
        """Refill tokens based on elapsed time."""
        now = self.clock()
        # __post_init__ guarantees last_refill is not None; don't use `or` —
        # it short-circuits on legitimate 0.0 timestamps from injected clocks.
        assert self.last_refill is not None
        elapsed = now - self.last_refill
        tokens_to_add = elapsed * self.capacity
        self.tokens = min(self.capacity, self.tokens + tokens_to_add)
        self.last_refill = now

    async def acquire(self, timeout: Optional[float] = None) -> bool:
        """Acquire a token, waiting if necessary."""
        start_time = self.clock()
        deadline = start_time + timeout if timeout else None

        while True:
            self.refill()

            if self.tokens >= 1:
                self.tokens -= 1
                wait_time = self.clock() - start_time
                if wait_time > 0.01:  # Only record meaningful waits
                    metrics.record_queue_wait(self.endpoint, wait_time)
                return True

            # Check deadline
            if deadline and self.clock() >= deadline:
                logger.warning(f"Token acquisition timeout for {self.endpoint}")
                return False

            # Check queue depth for back-pressure
            if len(self.queue) > 100:
                logger.error(f"Queue depth exceeded for {self.endpoint}, failing fast")
                raise Exception(f"Rate limit queue full for {self.endpoint}")

            # Wait with jitter
            wait_time = (1.0 / self.capacity) * random.uniform(0.5, 1.5)
            wait_time = min(wait_time, 1.0)  # Cap at 1 second

            if deadline:
                wait_time = min(wait_time, max(0, deadline - self.clock()))

            await asyncio.sleep(wait_time)


# Per-endpoint-region token buckets
token_buckets: Dict[Tuple[str, str], TokenBucket] = {}

# Default TPS limits per endpoint family (from Amazon docs)
DEFAULT_TPS_LIMITS = {
    "/v2/campaigns": 10,
    "/v2/ad-groups": 10,
    "/v2/keywords": 10,
    "/v2/product-ads": 10,
    "/v2/profiles": 5,
    "/reporting": 2,
    "/amc": 1,
    "/exports": 1,
    "default": 5,
}


def get_endpoint_family(url: str) -> str:
    """Extract endpoint family from URL."""
    path = urlparse(url).path.lower()

    # Match specific patterns
    if "/v2/campaigns" in path:
        return "/v2/campaigns"
    elif "/v2/ad-groups" in path:
        return "/v2/ad-groups"
    elif "/v2/keywords" in path:
        return "/v2/keywords"
    elif "/v2/product-ads" in path:
        return "/v2/product-ads"
    elif "/v2/profiles" in path:
        return "/v2/profiles"
    elif "/reporting" in path:
        return "/reporting"
    elif "/amc/" in path:
        return "/amc"
    elif "/exports" in path:
        return "/exports"

    return "default"


def get_region_from_url(url: str) -> str:
    """Extract region from URL."""
    return RegionConfig.get_region_from_url(url)


def get_token_bucket(url: str, tps_override: Optional[float] = None) -> TokenBucket:
    """Get or create token bucket for endpoint/region."""
    endpoint_family = get_endpoint_family(url)
    region = get_region_from_url(url)
    key = (endpoint_family, region)

    if key not in token_buckets:
        tps = tps_override or DEFAULT_TPS_LIMITS.get(
            endpoint_family, DEFAULT_TPS_LIMITS["default"]
        )
        token_buckets[key] = TokenBucket(
            capacity=tps, tokens=tps, endpoint=endpoint_family, region=region
        )
        logger.info(f"Created token bucket: {endpoint_family}/{region} with {tps} TPS")

    return token_buckets[key]


def parse_retry_after(response: httpx.Response) -> Optional[float]:
    """Parse Retry-After header from response.

    Supports both delta-seconds and HTTP-date formats.
    """
    retry_after = response.headers.get("retry-after", "").strip()
    if not retry_after:
        return None

    try:
        # Try delta-seconds first (allow decimals)
        try:
            delay = float(retry_after)
        except ValueError:
            delay = None
        else:
            if delay >= 0:
                logger.debug(f"Parsed Retry-After as delta-seconds: {delay}")
                return delay

        # Try HTTP-date format
        from email.utils import parsedate_to_datetime

        retry_date = parsedate_to_datetime(retry_after)
        delay = (retry_date - datetime.now(retry_date.tzinfo)).total_seconds()
        delay = max(0, delay)  # Ensure non-negative
        logger.debug(f"Parsed Retry-After as HTTP-date: {delay}s")
        return delay
    except Exception as e:
        logger.warning(f"Failed to parse Retry-After header '{retry_after}': {e}")
        return None


def should_retry_status(status_code: int) -> bool:
    """Determine if status code is retryable."""
    # Retry: 429, 408, 502, 503, 504
    return status_code in {429, 408, 502, 503, 504}


def is_idempotent_request(request: httpx.Request) -> bool:
    """Check if request is idempotent."""
    method = request.method.upper()

    # GET, HEAD, PUT, DELETE are idempotent
    if method in {"GET", "HEAD", "PUT", "DELETE"}:
        return True

    # POST with idempotency key
    if method == "POST":
        headers = request.headers
        if "idempotency-key" in headers or "x-amzn-idempotency-key" in headers:
            return True

    return False


class ResilientRetry:
    """Enhanced retry decorator with all Amazon recommendations."""

    def __init__(
        self,
        max_attempts: int = 5,
        initial_delay: float = 1.0,
        max_delay: float = 60.0,
        backoff_multiplier: float = 2.0,
        total_timeout: float = 180.0,  # 3 minutes default
        use_circuit_breaker: bool = True,
        use_rate_limiter: bool = True,
        interactive: bool = False,  # True for user-facing, False for batch
    ):
        self.max_attempts = max_attempts if not interactive else min(5, max_attempts)
        self.initial_delay = initial_delay
        self.max_delay = max_delay
        self.backoff_multiplier = backoff_multiplier
        self.total_timeout = total_timeout
        self.use_circuit_breaker = use_circuit_breaker
        self.use_rate_limiter = use_rate_limiter

    def __call__(self, func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        async def wrapper(*args, **kwargs) -> T:
            start_time = time.time()
            last_exception: Optional[Exception] = None
            current_delay = self.initial_delay

            # Extract URL from request if available
            url = ""
            request = None
            for arg in args:
                if isinstance(arg, httpx.Request):
                    request = arg
                    url = str(request.url)
                    break

            endpoint = get_endpoint_family(url) if url else "unknown"
            region = get_region_from_url(url) if url else "unknown"

            # Check circuit breaker
            if self.use_circuit_breaker and url:
                breaker = get_circuit_breaker(endpoint)
                if breaker.is_open():
                    raise Exception(f"Circuit breaker OPEN for {endpoint}")

            for attempt in range(1, self.max_attempts + 1):
                try:
                    # Check total timeout budget
                    elapsed = time.time() - start_time
                    if elapsed >= self.total_timeout:
                        logger.error(f"Total retry budget exhausted ({elapsed:.1f}s)")
                        raise Exception(f"Retry timeout after {elapsed:.1f}s")

                    # Rate limiting
                    if self.use_rate_limiter and url:
                        bucket = get_token_bucket(url)
                        remaining_time = self.total_timeout - elapsed
                        acquired = await bucket.acquire(timeout=remaining_time)
                        if not acquired:
                            raise Exception(f"Rate limit timeout for {endpoint}")

                    # Make the actual call
                    result = await func(*args, **kwargs)

                    # Record success
                    if self.use_circuit_breaker and url:
                        breaker = get_circuit_breaker(endpoint)
                        breaker.record_success()

                    if attempt > 1:
                        metrics.record_success_after_retry(endpoint, attempt)

                    return result

                except (
                    httpx.HTTPStatusError,
                    httpx.RequestError,
                    httpx.TimeoutException,
                ) as e:
                    last_exception = e

                    # Determine if we should retry
                    should_retry = False
                    retry_after_delay: Optional[float] = None

                    if isinstance(e, httpx.HTTPStatusError):
                        status_code = e.response.status_code

                        # Check if status is retryable
                        if should_retry_status(status_code):
                            should_retry = True

                            # Record throttle
                            if status_code == 429:
                                metrics.record_throttle(endpoint, region)

                            # Check for Retry-After header
                            retry_after_delay = parse_retry_after(e.response)
                            if retry_after_delay:
                                metrics.record_retry_after(endpoint, retry_after_delay)

                        # For 4xx errors, only retry if idempotent
                        elif 400 <= status_code < 500:
                            if request and is_idempotent_request(request):
                                logger.debug(
                                    f"Retrying idempotent request despite {status_code}"
                                )
                                should_retry = True

                    elif isinstance(e, (httpx.RequestError, httpx.TimeoutException)):
                        # Network errors and timeouts are retryable
                        should_retry = True

                    # Do NOT record a circuit-breaker failure per attempt:
                    # with max_attempts=3 every transient error would
                    # count as 3 failures and trip the breaker after a
                    # single logical request. Count at most one failure
                    # per logical request, recorded only when we exit
                    # the loop without success.

                    if not should_retry or attempt >= self.max_attempts:
                        logger.error(f"Request failed after {attempt} attempts: {e}")
                        if self.use_circuit_breaker and url:
                            breaker = get_circuit_breaker(endpoint)
                            breaker.record_failure()
                        raise

                    # Calculate delay
                    if retry_after_delay:
                        # Honor Retry-After with jitter
                        delay = retry_after_delay + random.uniform(
                            0, min(retry_after_delay * 0.1, 5)
                        )
                    else:
                        # Full jitter exponential backoff
                        delay = random.uniform(0, min(current_delay, self.max_delay))
                        current_delay = min(
                            current_delay * self.backoff_multiplier,
                            self.max_delay,
                        )

                    # Ensure delay doesn't exceed remaining budget
                    remaining_time = self.total_timeout - (time.time() - start_time)
                    delay = min(delay, remaining_time - 1)  # Leave 1s for the request

                    if delay <= 0:
                        logger.error("No time left in retry budget")
                        if self.use_circuit_breaker and url:
                            breaker = get_circuit_breaker(endpoint)
                            breaker.record_failure()
                        raise

                    metrics.record_retry(endpoint, attempt, delay)
                    logger.info(
                        f"Retry {attempt}/{self.max_attempts} after {delay:.2f}s for {endpoint}"
                    )

                    await asyncio.sleep(delay)

            # Should never reach here
            if last_exception:
                raise last_exception
            raise Exception("Retry logic error")

        return wrapper

    @classmethod
    def for_interactive(cls) -> "ResilientRetry":
        """Create retry config optimized for interactive/user-facing requests."""
        return cls(
            max_attempts=5,
            total_timeout=120,
            interactive=True,  # 2 minutes
        )

    @classmethod
    def for_batch(cls) -> "ResilientRetry":
        """Create retry config optimized for batch/background operations."""
        return cls(
            max_attempts=10,
            total_timeout=300,
            interactive=False,  # 5 minutes
        )


# Export convenience decorators
resilient_retry = ResilientRetry()
interactive_retry = ResilientRetry.for_interactive()
batch_retry = ResilientRetry.for_batch()
