"""Unit tests for the path normalizer (Task 22 ruling #7).

Not skipif-guarded: ``amazon_ads_mcp.metering.normalizer`` has no
dependency on ``mcp_outbound_metering`` (only ``httpx``, already a core
dependency), so it is safe -- and useful -- to test on every supported
Python version, same rationale as ``test_compat_guard.py``.
"""

from __future__ import annotations

import httpx
import pytest

from amazon_ads_mcp.metering.normalizer import normalize_path


def _req(path: str) -> httpx.Request:
    return httpx.Request("GET", f"https://advertising-api.amazon.com{path}")


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/v2/profiles", "/v2/profiles"),
        ("/v2/campaigns/42", "/v2/campaigns/{id}"),
        ("/v2/campaigns/42/adGroups/7", "/v2/campaigns/{id}/adGroups/{id}"),
        ("/v2/profiles/A1B2C3D4E5F6", "/v2/profiles/{id}"),
        (
            "/reporting/reports/550e8400-e29b-41d4-a716-446655440000",
            "/reporting/reports/{id}",
        ),
        ("/v2/campaigns", "/v2/campaigns"),
    ],
)
def test_normalize_path_collapses_high_cardinality_segments(path: str, expected: str) -> None:
    assert normalize_path(_req(path)) == expected


def test_normalize_path_never_includes_query_string() -> None:
    request = httpx.Request(
        "GET",
        "https://advertising-api.amazon.com/v2/campaigns/42",
        params={"token": "s3cret"},
    )
    result = normalize_path(request)
    assert "?" not in result
    assert "token" not in result
    assert "s3cret" not in result
    assert result == "/v2/campaigns/{id}"


def test_normalize_path_short_alpha_segment_is_stable() -> None:
    # A short alpha-only segment (not a pure-digit, not an Amazon entity-id
    # shape, not a UUID) must never be collapsed.
    assert normalize_path(_req("/v2/profiles/summary")) == "/v2/profiles/summary"
