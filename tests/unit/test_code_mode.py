"""Tests for Code Mode integration.

Tests cover settings, tagging, discovery tools, dependency guards,
and interaction with progressive disclosure.
"""

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Settings tests
# ---------------------------------------------------------------------------


class TestCodeModeSettings:
    """Verify code mode settings load correctly from environment."""

    def test_code_mode_disabled_by_default(self):
        """CODE_MODE defaults to False."""
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CODE_MODE", None)
            from amazon_ads_mcp.config.settings import Settings

            s = Settings(
                _env_file=None,
                ad_api_client_id="x",
                ad_api_client_secret="y",
                ad_api_refresh_token="z",
            )
            assert s.code_mode_enabled is False

    def test_code_mode_enabled_via_env(self):
        """CODE_MODE=true enables code mode."""
        with patch.dict(os.environ, {"CODE_MODE": "true"}, clear=False):
            from amazon_ads_mcp.config.settings import Settings

            s = Settings(
                _env_file=None,
                ad_api_client_id="x",
                ad_api_client_secret="y",
                ad_api_refresh_token="z",
            )
            assert s.code_mode_enabled is True

    def test_code_mode_include_tags_default_true(self):
        """Tags are included by default."""
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CODE_MODE_INCLUDE_TAGS", None)
            from amazon_ads_mcp.config.settings import Settings

            s = Settings(
                _env_file=None,
                ad_api_client_id="x",
                ad_api_client_secret="y",
                ad_api_refresh_token="z",
            )
            assert s.code_mode_include_tags is True

    def test_code_mode_include_tags_opt_out(self):
        """Tags can be disabled with CODE_MODE_INCLUDE_TAGS=false."""
        with patch.dict(
            os.environ, {"CODE_MODE_INCLUDE_TAGS": "false"}, clear=False
        ):
            from amazon_ads_mcp.config.settings import Settings

            s = Settings(
                _env_file=None,
                ad_api_client_id="x",
                ad_api_client_secret="y",
                ad_api_refresh_token="z",
            )
            assert s.code_mode_include_tags is False

    def test_code_mode_sandbox_defaults(self):
        """Sandbox defaults are sensible."""
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CODE_MODE_MAX_DURATION_SECS", None)
            os.environ.pop("CODE_MODE_MAX_MEMORY", None)
            from amazon_ads_mcp.config.settings import Settings

            s = Settings(
                _env_file=None,
                ad_api_client_id="x",
                ad_api_client_secret="y",
                ad_api_refresh_token="z",
            )
            assert s.code_mode_max_duration_secs == 30
            assert s.code_mode_max_memory == 50_000_000


# ---------------------------------------------------------------------------
# Code mode module tests (import/dependency guards)
# ---------------------------------------------------------------------------


class TestCodeModeDependencyGuard:
    """Test that missing fastmcp[code-mode] produces clear errors."""

    def test_build_discovery_tools_import_error(self):
        """build_discovery_tools raises ImportError when extra missing."""
        with patch.dict(
            "sys.modules",
            {"fastmcp.experimental.transforms.code_mode": None},
        ):
            from amazon_ads_mcp.server.code_mode import build_discovery_tools

            with pytest.raises(ImportError, match="code-mode"):
                build_discovery_tools()

    def test_create_transform_import_error(self):
        """create_code_mode_transform raises ImportError when extra missing."""
        with patch.dict(
            "sys.modules",
            {"fastmcp.experimental.transforms.code_mode": None},
        ):
            from amazon_ads_mcp.server.code_mode import (
                create_code_mode_transform,
            )

            with pytest.raises(ImportError, match="code-mode"):
                create_code_mode_transform()


# ---------------------------------------------------------------------------
# Discovery tool composition tests
# ---------------------------------------------------------------------------


class TestDiscoveryTools:
    """Test that discovery tools are built correctly based on settings."""

    @staticmethod
    def _make_mock_classes():
        class MockGetTags:
            pass

        class MockSearch:
            pass

        class MockGetSchemas:
            pass

        return MockGetTags, MockSearch, MockGetSchemas

    @staticmethod
    def _make_mock_module():
        MockGetTags, MockSearch, MockGetSchemas = (
            TestDiscoveryTools._make_mock_classes()
        )
        mock_mod = MagicMock()
        mock_mod.GetTags = MockGetTags
        mock_mod.Search = MockSearch
        mock_mod.GetSchemas = MockGetSchemas
        return mock_mod

    def _run_with_include_tags(self, include_tags: bool):
        """Run build_discovery_tools with a specific include_tags value."""
        import amazon_ads_mcp.server.code_mode as cm

        mock_mod = self._make_mock_module()
        original_settings = cm.settings

        mock_settings = MagicMock()
        mock_settings.code_mode_include_tags = include_tags
        cm.settings = mock_settings

        try:
            with patch.dict(
                "sys.modules",
                {"fastmcp.experimental.transforms.code_mode": mock_mod},
            ):
                return cm.build_discovery_tools()
        finally:
            cm.settings = original_settings

    def test_default_includes_tags(self):
        """Default (include_tags=True) produces [GetTags, Search, GetSchemas]."""
        tools = self._run_with_include_tags(True)
        assert len(tools) == 3
        type_names = [type(t).__name__ for t in tools]
        assert type_names == ["MockGetTags", "MockSearch", "MockGetSchemas"]

    def test_without_tags(self):
        """include_tags=False produces [Search, GetSchemas]."""
        tools = self._run_with_include_tags(False)
        assert len(tools) == 2
        type_names = [type(t).__name__ for t in tools]
        assert type_names == ["MockSearch", "MockGetSchemas"]

    def test_search_and_schemas_always_present(self):
        """Search and GetSchemas are always included regardless of tags setting."""
        for include_tags in [True, False]:
            tools = self._run_with_include_tags(include_tags)
            type_names = [type(t).__name__ for t in tools]
            assert "MockSearch" in type_names
            assert "MockGetSchemas" in type_names


# ---------------------------------------------------------------------------
# Tagging tests
# ---------------------------------------------------------------------------


class TestToolTagging:
    """Test tool tagging for code mode discovery."""

    @pytest.mark.asyncio
    async def test_tag_tools_by_prefix(self):
        """Tools are tagged with human-readable category names."""
        from amazon_ads_mcp.server.code_mode import (
            tag_tools_by_prefix,
        )

        mock_tool = MagicMock()
        mock_tool.tags = None
        mock_tool.name = "listCampaigns"

        mock_tool_info = MagicMock()
        mock_tool_info.name = "listCampaigns"

        mock_sub_server = AsyncMock()
        mock_sub_server.list_tools.return_value = [mock_tool_info]
        mock_sub_server.get_tool.return_value = mock_tool

        mock_server = AsyncMock()
        mounted = {"cm": [mock_sub_server]}

        count = await tag_tools_by_prefix(mock_server, mounted)
        assert count == 1
        assert "campaign-management" in mock_tool.tags

    @pytest.mark.asyncio
    async def test_tag_tools_preserves_existing_tags(self):
        """Tagging adds to existing tags rather than replacing."""
        from amazon_ads_mcp.server.code_mode import tag_tools_by_prefix

        mock_tool = MagicMock()
        mock_tool.tags = {"existing-tag"}
        mock_tool.name = "listCampaigns"

        mock_tool_info = MagicMock()
        mock_tool_info.name = "listCampaigns"

        mock_sub_server = AsyncMock()
        mock_sub_server.list_tools.return_value = [mock_tool_info]
        mock_sub_server.get_tool.return_value = mock_tool

        mounted = {"sp": [mock_sub_server]}
        await tag_tools_by_prefix(AsyncMock(), mounted)

        assert "existing-tag" in mock_tool.tags
        assert "sponsored-products" in mock_tool.tags

    @pytest.mark.asyncio
    async def test_tag_builtin_tools(self):
        """Builtin tools are tagged as server-management."""
        from amazon_ads_mcp.server.code_mode import BUILTIN_TAG, tag_builtin_tools

        mock_tool = MagicMock()
        mock_tool.tags = None

        mock_tool_info = MagicMock()
        mock_tool_info.name = "set_active_profile"

        mock_server = AsyncMock()
        mock_server.list_tools.return_value = [mock_tool_info]
        mock_server.get_tool.return_value = mock_tool

        count = await tag_builtin_tools(mock_server)
        assert count == 1
        assert BUILTIN_TAG in mock_tool.tags

    @pytest.mark.asyncio
    async def test_tag_unknown_prefix_uses_prefix_as_tag(self):
        """Unknown prefixes use the prefix itself as the tag."""
        from amazon_ads_mcp.server.code_mode import tag_tools_by_prefix

        mock_tool = MagicMock()
        mock_tool.tags = None
        mock_tool.name = "someTool"

        mock_tool_info = MagicMock()
        mock_tool_info.name = "someTool"

        mock_sub_server = AsyncMock()
        mock_sub_server.list_tools.return_value = [mock_tool_info]
        mock_sub_server.get_tool.return_value = mock_tool

        mounted = {"unknown_prefix": [mock_sub_server]}
        await tag_tools_by_prefix(AsyncMock(), mounted)

        assert "unknown_prefix" in mock_tool.tags


# ---------------------------------------------------------------------------
# Server builder integration tests
# ---------------------------------------------------------------------------


class TestServerBuilderCodeMode:
    """Test code mode integration in ServerBuilder."""

    @pytest.mark.asyncio
    async def test_code_mode_supersedes_progressive_disclosure(self):
        """When code mode active, tool group tools are not registered."""
        from amazon_ads_mcp.server.builtin_tools import (
            register_all_builtin_tools,
        )

        server = MagicMock()
        server.tool = MagicMock(return_value=lambda f: f)

        registered_tool_names = []

        def tracking_tool(**kwargs):
            name = kwargs.get("name", "")
            registered_tool_names.append(name)
            return lambda f: f

        server.tool = tracking_tool

        with patch(
            "amazon_ads_mcp.server.builtin_tools.get_auth_manager"
        ) as mock_auth:
            mock_auth.return_value = MagicMock(provider=None)

            await register_all_builtin_tools(
                server,
                mounted_servers={"cm": [MagicMock()]},
                group_tool_counts={"cm": 5},
                skip_tool_groups=True,
            )

        assert "list_tool_groups" not in registered_tool_names
        assert "enable_tool_group" not in registered_tool_names

    @pytest.mark.asyncio
    async def test_tool_groups_registered_when_not_skipped(self):
        """Without skip_tool_groups, tool group tools ARE registered."""
        from amazon_ads_mcp.server.builtin_tools import (
            register_all_builtin_tools,
        )

        server = MagicMock()
        registered_tool_names = []

        def tracking_tool(**kwargs):
            name = kwargs.get("name", "")
            registered_tool_names.append(name)
            return lambda f: f

        server.tool = tracking_tool

        with patch(
            "amazon_ads_mcp.server.builtin_tools.get_auth_manager"
        ) as mock_auth:
            mock_auth.return_value = MagicMock(provider=None)

            await register_all_builtin_tools(
                server,
                mounted_servers={"cm": [MagicMock()]},
                group_tool_counts={"cm": 5},
                skip_tool_groups=False,
            )

        assert "list_tool_groups" in registered_tool_names
        assert "enable_tool_group" in registered_tool_names


# ---------------------------------------------------------------------------
# Prefix mapping completeness
# ---------------------------------------------------------------------------


class TestPrefixMapping:
    """Verify PREFIX_TO_TAG covers known prefixes."""

    def test_known_prefixes_have_tags(self):
        """All prefixes from packages.json are in PREFIX_TO_TAG."""
        from amazon_ads_mcp.server.code_mode import PREFIX_TO_TAG

        required = ["cm", "sp", "sb", "sd", "dsp", "amc", "ac", "rp", "br", "st"]
        for prefix in required:
            assert prefix in PREFIX_TO_TAG, f"Missing tag for prefix '{prefix}'"

    def test_tags_are_human_readable(self):
        """Tags should be lowercase kebab-case strings."""
        from amazon_ads_mcp.server.code_mode import PREFIX_TO_TAG

        for prefix, tag in PREFIX_TO_TAG.items():
            assert tag == tag.lower(), f"Tag '{tag}' for prefix '{prefix}' not lowercase"
            assert " " not in tag, f"Tag '{tag}' contains spaces"
