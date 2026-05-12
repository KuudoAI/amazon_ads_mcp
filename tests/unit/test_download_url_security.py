import socket

import pytest

from amazon_ads_mcp.utils.security import validate_download_url


def test_validate_download_url_requires_https():
    with pytest.raises(Exception, match="https"):
        validate_download_url("http://s3.amazonaws.com/bucket/object")


def test_validate_download_url_rejects_broad_amazon_dot_com(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
        ],
    )

    with pytest.raises(Exception, match="allowed list"):
        validate_download_url("https://advertising-api.amazon.com/export.json")


def test_validate_download_url_rejects_private_resolution(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 443))
        ],
    )

    with pytest.raises(Exception, match="private|reserved"):
        validate_download_url("https://s3.amazonaws.com/bucket/object")


def test_validate_download_url_allows_public_cloudfront(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("54.230.1.1", 443))
        ],
    )

    assert (
        validate_download_url("https://d111111abcdef8.cloudfront.net/object")
        == "https://d111111abcdef8.cloudfront.net/object"
    )
