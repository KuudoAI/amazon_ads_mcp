"""Regression test: /health must report the real package version."""

from pathlib import Path

from amazon_ads_mcp import __version__


def _server_builder_source() -> str:
    server_builder_path = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "amazon_ads_mcp"
        / "server"
        / "server_builder.py"
    )
    return server_builder_path.read_text()


def test_health_check_reports_package_version():
    """The /health response should mirror the installed package version
    rather than a hardcoded placeholder. Orchestrators and operators
    depend on this for rollout/rollback tracking."""
    source = _server_builder_source()

    assert '"version": "1.0.0"' not in source
    assert "package_version" in source
    assert isinstance(__version__, str)
    assert __version__


def test_health_check_registers_orchestrator_aliases():
    """Load balancers and Kubernetes probes hit /healthz (k8s/GCE
    convention) and bare / — both must return 200 alongside /health,
    or upstream proxies will log a flood of 404s and may mark the
    container unhealthy."""
    source = _server_builder_source()

    assert 'custom_route("/health", methods=["GET"])' in source
    assert 'custom_route("/healthz", methods=["GET"])' in source
    assert 'custom_route("/", methods=["GET"])' in source
