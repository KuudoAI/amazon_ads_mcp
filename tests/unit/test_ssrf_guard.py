"""Tests for SSRF protection in validate_download_url."""

import os
import socket
from unittest.mock import patch

import pytest

from amazon_ads_mcp.utils.errors import ValidationError
from amazon_ads_mcp.utils.security import validate_download_url


def _fake_resolve_public(host, port, family):
    """Return a fake public IP for any host."""
    return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("52.94.236.1", 0))]


def _fake_resolve_private(host, port, family):
    """Return a private IP."""
    return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.1", 0))]


def _fake_resolve_metadata(host, port, family):
    """Return the link-local metadata IP."""
    return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("169.254.169.254", 0))]


def _fake_resolve_loopback(host, port, family):
    return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 0))]


def _fake_resolve_fail(host, port, family):
    raise socket.gaierror("nope")


class TestValidateDownloadUrl:
    @patch("amazon_ads_mcp.utils.security.socket.getaddrinfo", _fake_resolve_public)
    def test_allows_s3_amazonaws(self):
        url = "https://offline-report-storage.s3.amazonaws.com/exports/abc"
        assert validate_download_url(url) == url

    @patch("amazon_ads_mcp.utils.security.socket.getaddrinfo", _fake_resolve_public)
    def test_allows_cloudfront(self):
        url = "https://d1234.cloudfront.net/report.json.gz"
        assert validate_download_url(url) == url

    def test_rejects_empty(self):
        with pytest.raises(ValidationError):
            validate_download_url("")

    def test_rejects_non_http_scheme(self):
        with pytest.raises(ValidationError, match="scheme"):
            validate_download_url("ftp://s3.amazonaws.com/file")

    @patch("amazon_ads_mcp.utils.security.socket.getaddrinfo", _fake_resolve_public)
    def test_rejects_non_allowed_host(self):
        with pytest.raises(ValidationError, match="not in allowed list"):
            validate_download_url("https://evil.com/steal")

    @patch("amazon_ads_mcp.utils.security.socket.getaddrinfo", _fake_resolve_metadata)
    def test_rejects_metadata_ip(self):
        with pytest.raises(ValidationError, match="private/reserved"):
            validate_download_url(
                "http://169.254.169.254/latest/meta-data/",
                allowed_host_suffixes=[],
            )

    @patch("amazon_ads_mcp.utils.security.socket.getaddrinfo", _fake_resolve_loopback)
    def test_rejects_localhost(self):
        with pytest.raises(ValidationError):
            validate_download_url("http://localhost:8080/secret", allowed_host_suffixes=[])

    @patch("amazon_ads_mcp.utils.security.socket.getaddrinfo", _fake_resolve_private)
    def test_rejects_private_ip(self):
        with pytest.raises(ValidationError, match="private/reserved"):
            validate_download_url(
                "http://10.0.0.1/internal",
                allowed_host_suffixes=[],
            )

    @patch("amazon_ads_mcp.utils.security.socket.getaddrinfo", _fake_resolve_public)
    def test_custom_allowlist(self):
        url = "https://mycdn.example.org/file"
        assert validate_download_url(url, [".example.org"]) == url

    @patch("amazon_ads_mcp.utils.security.socket.getaddrinfo", _fake_resolve_public)
    def test_empty_allowlist_allows_public(self):
        url = "https://public-server.com/file"
        assert validate_download_url(url, allowed_host_suffixes=[]) == url

    @patch.dict(os.environ, {"AMAZON_ADS_ALLOW_PRIVATE_DOWNLOAD_HOSTS": "true"})
    def test_bypass_env_var(self):
        url = "http://localhost:9090/test"
        assert validate_download_url(url) == url

    def test_rejects_no_hostname(self):
        with pytest.raises(ValidationError, match="hostname"):
            validate_download_url("https:///path")

    @patch("amazon_ads_mcp.utils.security.socket.getaddrinfo", _fake_resolve_fail)
    def test_rejects_unresolvable_host(self):
        with pytest.raises(ValidationError, match="Cannot resolve"):
            validate_download_url(
                "https://nonexistent.amazonaws.com/file",
            )

    @patch("amazon_ads_mcp.utils.security.socket.getaddrinfo", _fake_resolve_loopback)
    def test_rejects_dns_rebinding_to_loopback(self):
        """Host passes allowlist but DNS resolves to loopback."""
        with pytest.raises(ValidationError, match="private/reserved"):
            validate_download_url("https://evil.amazonaws.com/steal")
