"""Unit tests for HTTP utilities.

This module tests the HTTP client manager, retry logic, and
other HTTP-related utility functions.
"""

import asyncio

import httpx
import asyncio as _asyncio
from unittest.mock import patch

from amazon_ads_mcp.utils.http import HTTPClientManager, async_retry, create_timeout, create_limits


def test_http_client_manager_caches():
    m = HTTPClientManager()
    c1 = asyncio.run(m.get_client(base_url="https://example.com"))
    c2 = asyncio.run(m.get_client(base_url="https://example.com"))
    assert c1 is c2
    asyncio.run(m.close_all())


def test_http_client_manager_cache_key_stable_same_values():
    m = HTTPClientManager()
    t1 = create_timeout(5, 30, 10, 5)
    t2 = create_timeout(5, 30, 10, 5)  # distinct object, same values
    l1 = create_limits(10, 20, 30.0)
    l2 = create_limits(10, 20, 30.0)

    c1 = asyncio.run(m.get_client(base_url="https://ex.com", timeout=t1, limits=l1))
    c2 = asyncio.run(m.get_client(base_url="https://ex.com", timeout=t2, limits=l2))
    assert c1 is c2
    _asyncio.run(m.close_all())


def test_async_retry_succeeds_after_failures():
    calls = {"n": 0}

    @async_retry(max_attempts=3, delay=0.01, backoff=1.0)
    async def sometimes():
        calls["n"] += 1
        if calls["n"] < 2:
            raise httpx.HTTPError("boom")
        return 42

    out = asyncio.run(sometimes())
    assert out == 42
    assert calls["n"] == 2


def test_async_retry_max_attempts():
    """Test that retry stops after max attempts."""
    calls = {"n": 0}

    @async_retry(max_attempts=3, delay=0.01, backoff=1.0, exceptions=(Exception,))
    async def always_fails():
        calls["n"] += 1
        raise ValueError("Always fails")

    try:
        asyncio.run(always_fails())
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert str(e) == "Always fails"
        assert calls["n"] == 3


def test_create_timeout_defaults():
    """Test timeout creation with default values."""
    timeout = create_timeout()
    assert timeout.connect == 5.0
    assert timeout.read == 30.0
    assert timeout.write == 10.0
    assert timeout.pool == 5.0


def test_create_limits_defaults():
    """Test limits creation with default values."""
    limits = create_limits()
    assert limits.max_keepalive_connections == 10
    assert limits.max_connections == 20
    assert limits.keepalive_expiry == 30.0


def test_http_client_manager_singleton():
    """Test that HTTPClientManager is a singleton."""
    m1 = HTTPClientManager()
    m2 = HTTPClientManager()
    assert m1 is m2


def test_http_client_manager_different_configs():
    """Test that different configs create different clients."""
    m = HTTPClientManager()
    
    # Different base URLs
    c1 = asyncio.run(m.get_client(base_url="https://api1.example.com"))
    c2 = asyncio.run(m.get_client(base_url="https://api2.example.com"))
    assert c1 is not c2
    
    # Different timeouts
    t1 = create_timeout(connect=5.0)
    t2 = create_timeout(connect=10.0)
    c3 = asyncio.run(m.get_client(timeout=t1))
    c4 = asyncio.run(m.get_client(timeout=t2))
    assert c3 is not c4
    
    asyncio.run(m.close_all())


def test_retry_jitter_applied():
    # Monkeypatch asyncio.sleep to capture delay
    sleeps = []

    async def fake_sleep(d):
        sleeps.append(d)

    calls = {"n": 0}

    @async_retry(max_attempts=2, delay=1.0, backoff=1.0)
    async def sometimes():
        calls["n"] += 1
        if calls["n"] < 2:
            raise httpx.HTTPError("boom")
        return 7

    with patch("asyncio.sleep", fake_sleep):
        out = asyncio.run(sometimes())
    assert out == 7
    assert len(sleeps) == 1
    assert 0.8 <= sleeps[0] <= 1.2


def test_http2_env_toggle_does_not_crash_without_h2(monkeypatch):
    m = HTTPClientManager()
    # First with HTTP/2 disabled
    monkeypatch.setenv("HTTP_ENABLE_HTTP2", "false")
    _ = asyncio.run(m.get_client(base_url="https://ex2.com"))
    # Then enable and request again; should not crash even if h2 missing
    monkeypatch.setenv("HTTP_ENABLE_HTTP2", "true")
    c2 = asyncio.run(m.get_client(base_url="https://ex2.com"))
    assert c2 is not None
    _asyncio.run(m.close_all())
