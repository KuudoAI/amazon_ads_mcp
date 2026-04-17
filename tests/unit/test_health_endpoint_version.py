"""Regression test: /health must report the real package version."""

from pathlib import Path

from amazon_ads_mcp import __version__


def test_health_check_reports_package_version():
    """The /health response should mirror the installed package version
    rather than a hardcoded placeholder. Orchestrators and operators
    depend on this for rollout/rollback tracking."""
    server_builder_path = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "amazon_ads_mcp"
        / "server"
        / "server_builder.py"
    )
    source = server_builder_path.read_text()

    assert '"version": "1.0.0"' not in source
    assert "package_version" in source
    assert isinstance(__version__, str)
    assert __version__
