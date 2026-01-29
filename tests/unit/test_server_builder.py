import json
from types import SimpleNamespace

import pytest

from amazon_ads_mcp.server.server_builder import ServerBuilder


@pytest.fixture
def builder(monkeypatch):
    monkeypatch.setattr(
        "amazon_ads_mcp.server.server_builder.get_auth_manager",
        lambda: SimpleNamespace(provider=None),
    )
    return ServerBuilder()


@pytest.mark.asyncio
async def test_load_namespace_mapping_prefixes(tmp_path, builder):
    resources_dir = tmp_path / "resources"
    resources_dir.mkdir()
    packages = {"prefixes": {"Accounts": "accounts"}}
    (resources_dir / "packages.json").write_text(json.dumps(packages))

    mapping = await builder._load_namespace_mapping(resources_dir)

    assert mapping == {"Accounts": "accounts"}


@pytest.mark.asyncio
async def test_load_namespace_mapping_back_compat(tmp_path, builder):
    resources_dir = tmp_path / "resources"
    resources_dir.mkdir()
    packages = {"Accounts": {"prefix": "acct"}}
    (resources_dir / "packages.json").write_text(json.dumps(packages))

    mapping = await builder._load_namespace_mapping(resources_dir)

    assert mapping == {"Accounts": "acct"}


@pytest.mark.asyncio
async def test_load_package_allowlist_from_alias(tmp_path, builder, monkeypatch):
    resources_dir = tmp_path / "resources"
    resources_dir.mkdir()
    (resources_dir / "SponsoredProducts.json").write_text("{}")

    packages = {"aliases": {"sp": "SponsoredProducts"}}
    (resources_dir / "packages.json").write_text(json.dumps(packages))

    monkeypatch.setenv("AMAZON_AD_API_PACKAGES", "sp")

    allowlist = await builder._load_package_allowlist(resources_dir)

    assert allowlist == {"SponsoredProducts"}


@pytest.mark.asyncio
async def test_load_package_allowlist_defaults(tmp_path, builder, monkeypatch):
    resources_dir = tmp_path / "resources"
    resources_dir.mkdir()
    (resources_dir / "Profiles.json").write_text("{}")

    packages = {"defaults": ["profiles"]}
    (resources_dir / "packages.json").write_text(json.dumps(packages))

    monkeypatch.delenv("AMAZON_AD_API_PACKAGES", raising=False)

    allowlist = await builder._load_package_allowlist(resources_dir)

    assert allowlist == {"Profiles"}
