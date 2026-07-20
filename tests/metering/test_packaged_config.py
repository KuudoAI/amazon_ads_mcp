"""Fix round 2, deployment gap #1: metering.yaml must resolve correctly
in packaged/Docker deployments, not just a repo checkout.

Docker's runtime image copies the venv + dist/openapi + entrypoint into
/app but NOT the repo-root metering.yaml, and a wheel install only ships
package resources -- METERING_ENABLED=true without METERING_CONFIG would
otherwise resolve "metering.yaml" relative to CWD and fail to find it,
either failing strict startup or silently disabling metering. Fix:
metering.yaml is now ALSO packaged at
src/amazon_ads_mcp/metering/metering.yaml, and
amazon_ads_mcp.metering.config.resolve_config_path() falls back to it via
importlib.resources when no METERING_CONFIG is set and no ./metering.yaml
exists in CWD.
"""

from __future__ import annotations

import os
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT_CONFIG = REPO_ROOT / "metering.yaml"
PACKAGED_CONFIG = REPO_ROOT / "src" / "amazon_ads_mcp" / "metering" / "metering.yaml"


# -- drift guard: not skipif-guarded -- these are plain files, no --------
# -- mcp_outbound_metering dependency, so this runs on every Python ------
# -- version, same rationale as test_normalizer.py etc. -------------------


def test_packaged_config_matches_repo_root_byte_identical() -> None:
    """Drift guard: the packaged copy must be byte-identical to the
    tracked repo-root metering.yaml. If you edit one, edit both (or copy
    one over the other) -- this test exists specifically to catch the
    two silently diverging over time."""
    assert REPO_ROOT_CONFIG.is_file()
    assert PACKAGED_CONFIG.is_file()
    assert REPO_ROOT_CONFIG.read_bytes() == PACKAGED_CONFIG.read_bytes()


def test_packaged_config_is_schema_valid() -> None:
    import yaml
    from jsonschema import Draft202012Validator

    # Import lazily: catalog.schema_for lives in mcp_outbound_metering,
    # only available on 3.12 -- skip cleanly on <3.12 rather than failing
    # collection (this one check genuinely needs the producer package;
    # the byte-identity check above does not).
    pytest.importorskip("mcp_outbound_metering")
    from mcp_outbound_metering import catalog

    config = yaml.safe_load(PACKAGED_CONFIG.read_text(encoding="utf-8"))
    validator = Draft202012Validator(catalog.schema_for(catalog.METERING_CONFIG_V1))
    errors = list(validator.iter_errors(config))
    assert not errors, [e.message for e in errors]


# -- resolve_config_path() unit tests (no mcp_outbound_metering needed) --


def test_resolve_config_path_prefers_explicit_env(tmp_path, monkeypatch) -> None:
    from amazon_ads_mcp.metering.config import resolve_config_path

    explicit = tmp_path / "custom-metering.yaml"
    explicit.write_text("schema_version: 1\n")
    monkeypatch.chdir(tmp_path)

    resolved = resolve_config_path({"METERING_CONFIG": str(explicit)})
    assert resolved == explicit


def test_resolve_config_path_prefers_cwd_relative_over_packaged(tmp_path, monkeypatch) -> None:
    from amazon_ads_mcp.metering.config import resolve_config_path

    cwd_config = tmp_path / "metering.yaml"
    cwd_config.write_text("schema_version: 1\n")
    monkeypatch.chdir(tmp_path)

    resolved = resolve_config_path({})
    assert resolved.resolve() == cwd_config.resolve()


def test_resolve_config_path_falls_back_to_packaged_resource(tmp_path, monkeypatch) -> None:
    """The reviewer's exact packaged-deployment reproduction: chdir to an
    EMPTY tmp dir (no ./metering.yaml, mirroring /app in the Docker
    runtime image), no METERING_CONFIG -> resolves the packaged
    resource, and its content matches the repo-root file."""
    from amazon_ads_mcp.metering.config import resolve_config_path

    monkeypatch.chdir(tmp_path)
    assert not (tmp_path / "metering.yaml").exists()

    resolved = resolve_config_path({})
    assert resolved.is_file()
    assert resolved.read_bytes() == REPO_ROOT_CONFIG.read_bytes()


@pytest.mark.skipif(sys.version_info < (3, 12), reason="metering requires Python>=3.12")
def test_strict_startup_succeeds_from_packaged_config_in_empty_cwd(tmp_path, monkeypatch) -> None:
    """The reviewer's exact reproduction, end to end: strict
    METERING_ENABLED=true, an empty CWD (no ./metering.yaml), no
    METERING_CONFIG -> start_metering() succeeds by resolving the
    packaged resource, not by raising."""
    import asyncio

    from amazon_ads_mcp.metering import lifespan as metering_lifespan
    from amazon_ads_mcp.metering.adapter import get_metering_runtime, set_metering_runtime

    from ._support import base_env

    monkeypatch.chdir(tmp_path)
    workdir = tmp_path / "work"
    workdir.mkdir()
    assert not (tmp_path / "metering.yaml").exists()

    env = base_env(workdir)
    # No METERING_CONFIG -- must fall through to the packaged resource.
    env.pop("METERING_CONFIG", None)

    async def scenario():
        runtime = await metering_lifespan.start_metering(env=env)
        assert runtime is not None
        assert get_metering_runtime() is runtime
        await metering_lifespan.stop_metering()

    try:
        asyncio.run(scenario())
    finally:
        set_metering_runtime(None)


@pytest.mark.slow
def test_wheel_contains_the_packaged_metering_config(tmp_path) -> None:
    """Build a REAL wheel and inspect its contents directly, rather than
    trusting the pyproject.toml [[tool.poetry.include]] config in the
    abstract -- mirrors mcp_outbound_metering's own
    test_wheel_contains_the_install_templates (billing repo,
    packages/python/mcp_outbound_metering/tests/test_package.py)."""
    env = dict(os.environ)
    result = subprocess.run(
        ["uv", "build", "--wheel", "-o", str(tmp_path)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
    )
    assert result.returncode == 0, result.stdout + result.stderr

    wheels = list(tmp_path.glob("*.whl"))
    assert len(wheels) == 1, wheels

    with zipfile.ZipFile(wheels[0]) as archive:
        names = set(archive.namelist())
        assert "amazon_ads_mcp/metering/metering.yaml" in names
        packaged_bytes = archive.read("amazon_ads_mcp/metering/metering.yaml")

    assert packaged_bytes == REPO_ROOT_CONFIG.read_bytes()
