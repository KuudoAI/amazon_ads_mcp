"""Unit tests for the <3.12 compatibility guard (Task 22 ruling #2).

Unlike the rest of ``tests/metering/``, this module runs on EVERY supported
Python version, including the repo's 3.10 floor -- it is the test that
proves the guard behaves correctly on both sides of the 3.12 boundary. All
other ``tests/metering/*`` modules are ``skipif`` guarded (they exercise
the real ``mcp_outbound_metering`` package, which is only installed on
3.12); this one exercises the guard itself and must run everywhere.
"""

from __future__ import annotations

import logging
import sys

from amazon_ads_mcp.metering import compat


def test_compat_module_always_importable() -> None:
    """Importing amazon_ads_mcp.metering.compat must never raise, on any
    supported Python version -- that is the entire point of the guard."""
    assert hasattr(compat, "METERING_AVAILABLE")


def test_availability_matches_python_version_floor() -> None:
    if sys.version_info < compat.METERING_MIN_PYTHON:
        assert compat.METERING_AVAILABLE is False
        assert compat.MeteringRuntime is None
        assert compat.MeteringConfigError is None
        assert compat.MeteringError is None
    else:
        assert compat.METERING_AVAILABLE is True
        assert compat.MeteringRuntime is not None
        assert compat.MeteringConfigError is not None
        assert compat.MeteringError is not None


def test_warn_unsupported_logs_a_loud_warning(caplog) -> None:
    with caplog.at_level(logging.WARNING, logger="amazon_ads_mcp.metering.compat"):
        compat.warn_unsupported()
    assert any(
        "Python>=3.12" in record.message and record.levelno == logging.WARNING
        for record in caplog.records
    )


def test_warn_unsupported_names_the_install_extra(caplog) -> None:
    """Fix round 2, deployment gap #2: mcp-outbound-metering moved to the
    optional "metering" extra -- the operator-facing message must name
    the exact install command, not just say "not installed"."""
    with caplog.at_level(logging.WARNING, logger="amazon_ads_mcp.metering.compat"):
        compat.warn_unsupported()
    assert any(
        "amazon-ads-mcp[metering]" in record.message for record in caplog.records
    )
