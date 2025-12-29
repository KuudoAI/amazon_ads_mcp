import pytest

from amazon_ads_mcp.config.settings import Settings


@pytest.mark.unit
def test_openbridge_token_reads_from_openbridge_api_key(monkeypatch):
    monkeypatch.setenv("AUTH_METHOD", "openbridge")
    monkeypatch.delenv("AMAZON_AD_API_CLIENT_ID", raising=False)
    monkeypatch.delenv("AMAZON_AD_API_CLIENT_SECRET", raising=False)
    monkeypatch.delenv("AMAZON_AD_API_REFRESH_TOKEN", raising=False)
    monkeypatch.delenv("OPENBRIDGE_REFRESH_TOKEN", raising=False)

    monkeypatch.setenv("OPENBRIDGE_API_KEY", "ob-test-token")

    settings = Settings()
    assert settings.openbridge_refresh_token == "ob-test-token"
    assert settings.auth_method == "openbridge"


@pytest.mark.unit
def test_openbridge_refresh_token_takes_precedence_over_api_key(monkeypatch):
    monkeypatch.setenv("AUTH_METHOD", "openbridge")
    monkeypatch.delenv("AMAZON_AD_API_CLIENT_ID", raising=False)
    monkeypatch.delenv("AMAZON_AD_API_CLIENT_SECRET", raising=False)
    monkeypatch.delenv("AMAZON_AD_API_REFRESH_TOKEN", raising=False)

    monkeypatch.setenv("OPENBRIDGE_API_KEY", "ob-api-key")
    monkeypatch.setenv("OPENBRIDGE_REFRESH_TOKEN", "ob-refresh-token")

    settings = Settings()
    assert settings.openbridge_refresh_token == "ob-refresh-token"
    assert settings.auth_method == "openbridge"
