"""Unit tests for content type resolver.

This module tests the content type resolution functionality
that determines appropriate Accept headers for different
Amazon Ads API endpoints.
"""

from amazon_ads_mcp.utils.export_content_type_resolver import (
    get_export_accept_headers,
    get_measurement_accept_headers,
    get_brandmetrics_accept_headers,
    get_reports_download_accept_headers,
    resolve_download_accept_headers,
)


def test_export_accept_headers_ordering():
    # Unknown export id still returns all types preferring campaigns first only when known
    headers = get_export_accept_headers("")
    assert "application/vnd.campaignsexport.v1+json" in headers


def test_measurement_accept_pref_csv():
    h = get_measurement_accept_headers(prefer_csv=True)
    assert h[0].startswith("text/vnd.measurementresult")
    assert any(x.startswith("application/vnd.measurementresult") for x in h)


def test_brandmetrics_accept_versions():
    h = get_brandmetrics_accept_headers()
    assert h[0].endswith("v1.1+json")
    assert h[1].endswith("v1+json")


def test_reports_download_accept():
    h = get_reports_download_accept_headers()
    assert h == ["application/json"]


def test_resolve_download_accept_heuristics():
    # Exports by URL
    h = resolve_download_accept_headers("GET", "https://api/exports/ABC123")
    assert any("vnd." in x for x in h)

    # Measurement
    h2 = resolve_download_accept_headers("GET", "https://api/dsp/measurement/studies/123")
    assert any("measurementresult" in x for x in h2)

    # Reports/Snapshots
    h3 = resolve_download_accept_headers("GET", "https://api/v2/reports/xyz/download")
    assert h3 == ["application/json"]
    h4 = resolve_download_accept_headers("GET", "https://api/sp/snapshots/123/download")
    assert h4 == ["application/json"]

    # Brand Metrics
    h5 = resolve_download_accept_headers("GET", "https://api/insights/brandMetrics/report/abc")
    assert h5[0].endswith("v1.1+json")
