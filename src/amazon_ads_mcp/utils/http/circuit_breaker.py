"""Circuit breaker implementation for HTTP requests.

This module provides a circuit breaker pattern implementation designed
for HTTP operations. The circuit breaker helps prevent cascading failures
by temporarily stopping requests when a service is experiencing issues,
allowing it to recover before resuming normal operation.

The implementation supports configurable failure thresholds, recovery
timeouts, and exception types, making it suitable for various HTTP
client scenarios.
"""

import time
from functools import wraps
from typing import Any, Callable, Type

import httpx


class CircuitBreakerState:
    """Constants representing the possible states of a circuit breaker.

    The circuit breaker operates in three states:
    - CLOSED: Normal operation, requests are allowed
    - OPEN: Circuit is open, requests are blocked
    - HALF_OPEN: Testing if service has recovered
    """

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreaker:
    """Circuit breaker decorator for async functions.

    This class implements the circuit breaker pattern as a decorator
    that can be applied to async functions. It monitors failures and
    automatically opens the circuit when the failure threshold is
    reached, preventing further requests until the recovery timeout
    has elapsed.

    The circuit breaker supports custom failure thresholds, recovery
    timeouts, and exception types to handle different failure scenarios.
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0,
        expected_exception: Type[Exception] = httpx.RequestError,
    ):
        """Initialize the circuit breaker with configuration.

        :param failure_threshold: Number of consecutive failures before
                                 opening the circuit
        :type failure_threshold: int
        :param recovery_timeout: Time in seconds to wait before attempting
                                to reset the circuit
        :type recovery_timeout: float
        :param expected_exception: Exception type to monitor for failures
        :type expected_exception: Type[Exception]
        """
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception
        self.failure_count = 0
        self.last_failure_time = None
        self.state = CircuitBreakerState.CLOSED

    def __call__(self, func: Callable[..., Any]) -> Callable[..., Any]:
        """Apply the circuit breaker pattern to the decorated function.

        :param func: The async function to wrap with circuit breaker logic
        :type func: Callable[..., Any]
        :return: Wrapped function with circuit breaker behavior
        :rtype: Callable[..., Any]
        """

        @wraps(func)
        async def wrapper(*args, **kwargs):
            if self.state == CircuitBreakerState.OPEN:
                if self._should_attempt_reset():
                    self.state = CircuitBreakerState.HALF_OPEN
                else:
                    raise Exception("Circuit breaker is OPEN")
            try:
                result = await func(*args, **kwargs)
                self._on_success()
                return result
            except self.expected_exception:
                self._on_failure()
                raise

        return wrapper

    def _should_attempt_reset(self) -> bool:
        """Determine if enough time has passed to attempt resetting the circuit.

        :return: True if recovery timeout has elapsed, False otherwise
        :rtype: bool
        """
        return (
            self.last_failure_time is not None
            and time.monotonic() - self.last_failure_time
            >= self.recovery_timeout
        )

    def _on_success(self):
        """Handle successful function execution.

        Resets the failure count and closes the circuit, allowing
        normal operation to resume.
        """
        self.failure_count = 0
        self.state = CircuitBreakerState.CLOSED

    def _on_failure(self):
        """Handle function execution failure.

        Increments the failure count and records the failure time.
        Opens the circuit if the failure threshold is reached.
        """
        self.failure_count += 1
        self.last_failure_time = time.monotonic()
        if self.failure_count >= self.failure_threshold:
            self.state = CircuitBreakerState.OPEN
