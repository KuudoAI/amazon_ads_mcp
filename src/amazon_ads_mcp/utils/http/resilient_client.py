"""Resilient HTTP client with integrated retry, rate limiting, and circuit breaking.

This module provides a drop-in replacement for AuthenticatedClient that includes
all resilience patterns recommended by Amazon for API interactions.
"""

import logging
from typing import Any, Dict

import httpx

from ...utils.http_client import AuthenticatedClient
from .resilience import (
    ResilientRetry,
    get_circuit_breaker,
    get_endpoint_family,
    get_token_bucket,
    metrics,
)

logger = logging.getLogger(__name__)


class ResilientAuthenticatedClient(AuthenticatedClient):
    """Enhanced authenticated client with built-in resilience patterns.

    This client extends AuthenticatedClient to add:
    - Automatic retry with exponential backoff and jitter
    - Retry-After header support
    - Token bucket rate limiting per endpoint/region
    - Circuit breaker protection
    - Comprehensive metrics collection
    - Total retry budget enforcement

    It's a drop-in replacement that requires no code changes.
    """

    def __init__(
        self,
        *args,
        enable_rate_limiting: bool = True,
        enable_circuit_breaker: bool = True,
        interactive_mode: bool = False,
        **kwargs,
    ):
        """Initialize resilient client with configurable features.

        :param enable_rate_limiting: Enable token bucket rate limiting
        :param enable_circuit_breaker: Enable circuit breaker protection
        :param interactive_mode: Optimize for interactive (True) or batch (False)
        :param args: Positional arguments for parent class
        :param kwargs: Keyword arguments for parent class
        """
        super().__init__(*args, **kwargs)
        self.enable_rate_limiting = enable_rate_limiting
        self.enable_circuit_breaker = enable_circuit_breaker
        self.interactive_mode = interactive_mode

        # Configure retry based on mode
        if interactive_mode:
            self.retry_decorator = ResilientRetry.for_interactive()
        else:
            self.retry_decorator = ResilientRetry.for_batch()

        logger.info(
            f"ResilientAuthenticatedClient initialized: "
            f"rate_limiting={enable_rate_limiting}, "
            f"circuit_breaker={enable_circuit_breaker}, "
            f"mode={'interactive' if interactive_mode else 'batch'}"
        )

    async def send(self, request: httpx.Request, **kwargs) -> httpx.Response:
        """Send request with resilience patterns applied.

        Wraps the parent send method with:
        1. Pre-request rate limiting via token bucket
        2. Circuit breaker checking
        3. Retry logic with backoff and jitter
        4. Metrics collection

        :param request: The HTTP request to send
        :param kwargs: Additional arguments for send
        :return: The HTTP response
        :raises: Various HTTP exceptions after exhausting retries
        """
        url = str(request.url)
        endpoint = get_endpoint_family(url)

        # Pre-flight circuit breaker check
        if self.enable_circuit_breaker:
            breaker = get_circuit_breaker(endpoint)
            if breaker.is_open():
                logger.warning(f"Circuit breaker OPEN for {endpoint}, failing fast")
                raise Exception(f"Circuit breaker is OPEN for {endpoint}")

        # Apply rate limiting before sending
        if self.enable_rate_limiting:
            bucket = get_token_bucket(url)
            # Use shorter timeout for interactive mode
            timeout = 30.0 if self.interactive_mode else 120.0
            acquired = await bucket.acquire(timeout=timeout)
            if not acquired:
                logger.error(f"Rate limit timeout for {endpoint}")
                raise Exception(f"Rate limit acquisition timeout for {endpoint}")

        # Create wrapped send function for retry decorator
        @self.retry_decorator
        async def send_with_retry():
            return await super(ResilientAuthenticatedClient, self).send(
                request, **kwargs
            )

        # Execute with all resilience patterns
        try:
            response = await send_with_retry()

            # Record success in circuit breaker
            if self.enable_circuit_breaker:
                breaker = get_circuit_breaker(endpoint)
                breaker.record_success()

            # Capture rate-limit telemetry for the per-call context-var so
            # the meta-injection middleware can surface it as ``_meta.rate_limit``
            # on successful tool responses. See openbridge-mcp/CONTRACT.md.
            try:
                from .rate_limit_headers import (
                    extract_rate_limit_meta,
                    set_last_http_meta,
                )

                meta = extract_rate_limit_meta(response)
                if meta:
                    set_last_http_meta(meta)
            except Exception as exc:  # pragma: no cover - defensive
                logger.debug("Rate-limit meta capture failed: %s", exc)

            return response

        except Exception:
            # Record failure in circuit breaker
            if self.enable_circuit_breaker:
                breaker = get_circuit_breaker(endpoint)
                breaker.record_failure()
            raise

    async def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        """Make HTTP request with resilience patterns.

        Convenience method that builds request and sends with resilience.

        :param method: HTTP method
        :param url: Request URL
        :param kwargs: Additional request parameters
        :return: HTTP response
        """
        # Build request
        request = self.build_request(method, url, **kwargs)

        # Send with resilience
        return await self.send(request)

    def get_metrics(self) -> Dict[str, Any]:
        """Get collected resilience metrics.

        Returns metrics including:
        - Throttle counts per endpoint/region
        - Retry attempts and delays
        - Circuit breaker states
        - Queue wait times
        - Success after retry counts

        :return: Dictionary of collected metrics
        """
        return metrics.get_metrics()

    def reset_metrics(self) -> None:
        """Reset all collected metrics.

        Useful for testing or periodic metric collection.
        """
        global metrics
        from .resilience import MetricsCollector

        metrics = MetricsCollector()
        logger.info("Metrics reset")


def create_resilient_client(
    auth_manager=None,
    media_registry=None,
    header_resolver=None,
    interactive: bool = False,
    **kwargs,
) -> ResilientAuthenticatedClient:
    """Factory function to create a resilient authenticated client.

    :param auth_manager: Authentication manager
    :param media_registry: Media type registry
    :param header_resolver: Header name resolver
    :param interactive: Optimize for interactive (True) or batch (False)
    :param kwargs: Additional client configuration
    :return: Configured resilient client
    """
    return ResilientAuthenticatedClient(
        auth_manager=auth_manager,
        media_registry=media_registry,
        header_resolver=header_resolver,
        interactive_mode=interactive,
        **kwargs,
    )
