"""Coverage-pushing tests for ``utils.media.negotiator``.

Round-13 coverage report had this module at 26% (58 of 78 statements
uncovered). The class implements URL-based media-type negotiation for
export operations where the export ID encodes the resource shape.

Tests cover:
- ``_decode_export_id`` (base64 url-safe + standard variants)
- ``ResourceTypeNegotiator._extract_resource_type`` (with/without ``/v\\d+/``)
- ``_negotiate_exports`` suffix mapping (C, A, AD, R, T)
- ``negotiate()`` orchestration (no negotiator, exception-in-negotiator)
- Custom-negotiator registration
- ``EnhancedMediaTypeRegistry.resolve`` delegation + negotiation
"""

from __future__ import annotations

import base64

from unittest.mock import MagicMock

import pytest

from amazon_ads_mcp.utils.media.negotiator import (
    EnhancedMediaTypeRegistry,
    ResourceTypeNegotiator,
    _decode_export_id,
    create_enhanced_registry,
)


# --- _decode_export_id ----------------------------------------------------


class TestDecodeExportId:
    def test_decodes_url_safe_base64(self) -> None:
        plain = "campaign-123,C"
        encoded = base64.urlsafe_b64encode(plain.encode()).decode().rstrip("=")
        assert _decode_export_id(encoded) == plain

    def test_decodes_standard_base64(self) -> None:
        plain = "ad-456,AD"
        encoded = base64.b64encode(plain.encode()).decode().rstrip("=")
        assert _decode_export_id(encoded) == plain

    def test_decodes_with_padding(self) -> None:
        plain = "a"  # encodes to 4-char with 2 padding chars
        encoded_padded = base64.urlsafe_b64encode(plain.encode()).decode()
        # Strip padding to ensure the function adds it back
        encoded = encoded_padded.rstrip("=")
        assert _decode_export_id(encoded) == plain

    def test_garbage_returns_none(self) -> None:
        # Random non-base64 string: both decoders should fail.
        assert _decode_export_id("not!valid base64 ###") is None

    def test_empty_returns_empty_string_or_none(self) -> None:
        # base64 of "" is "" — both decoders return b"".decode() == "".
        # Document the actual behavior rather than asserting one specific value.
        result = _decode_export_id("")
        assert result in ("", None)


# --- ResourceTypeNegotiator._extract_resource_type ------------------------


class TestExtractResourceType:
    def test_extracts_first_path_segment(self) -> None:
        n = ResourceTypeNegotiator()
        assert n._extract_resource_type("https://x/exports/abc") == "exports"

    def test_strips_version_prefix(self) -> None:
        n = ResourceTypeNegotiator()
        assert n._extract_resource_type("https://x/v2/exports/abc") == "exports"

    def test_lowercases_result(self) -> None:
        n = ResourceTypeNegotiator()
        assert n._extract_resource_type("https://x/Exports/abc") == "exports"

    def test_no_path_returns_none(self) -> None:
        n = ResourceTypeNegotiator()
        # Plain host with no path → None
        assert n._extract_resource_type("https://x") is None


# --- _negotiate_exports ---------------------------------------------------


class TestNegotiateExports:
    def _build_url(self, suffix: str, prefix: str = "campaign-123") -> str:
        export_id = base64.urlsafe_b64encode(
            f"{prefix},{suffix}".encode()
        ).decode().rstrip("=")
        return f"https://api/exports/{export_id}"

    def test_campaigns_suffix_maps_to_v1_json(self) -> None:
        n = ResourceTypeNegotiator()
        url = self._build_url("C")
        result = n._negotiate_exports(
            "GET", url, ["application/vnd.campaignsexport.v1+json"]
        )
        assert result == "application/vnd.campaignsexport.v1+json"

    def test_adgroups_suffix_maps_to_v1_json(self) -> None:
        n = ResourceTypeNegotiator()
        url = self._build_url("A")
        result = n._negotiate_exports(
            "GET", url, ["application/vnd.adgroupsexport.v1+json"]
        )
        assert result == "application/vnd.adgroupsexport.v1+json"

    def test_ads_suffix_AD_maps_correctly(self) -> None:
        n = ResourceTypeNegotiator()
        url = self._build_url("AD")
        result = n._negotiate_exports(
            "GET", url, ["application/vnd.adsexport.v1+json"]
        )
        assert result == "application/vnd.adsexport.v1+json"

    def test_ads_suffix_R_alias_maps_correctly(self) -> None:
        """Documented quirk: some export IDs use ``,R`` for ads exports."""
        n = ResourceTypeNegotiator()
        url = self._build_url("R")
        result = n._negotiate_exports(
            "GET", url, ["application/vnd.adsexport.v1+json"]
        )
        assert result == "application/vnd.adsexport.v1+json"

    def test_targets_suffix_maps_to_v1_json(self) -> None:
        n = ResourceTypeNegotiator()
        url = self._build_url("T")
        result = n._negotiate_exports(
            "GET", url, ["application/vnd.targetsexport.v1+json"]
        )
        assert result == "application/vnd.targetsexport.v1+json"

    def test_non_get_returns_none(self) -> None:
        n = ResourceTypeNegotiator()
        url = self._build_url("C")
        assert n._negotiate_exports(
            "POST", url, ["application/vnd.campaignsexport.v1+json"]
        ) is None

    def test_url_without_export_id_returns_none(self) -> None:
        n = ResourceTypeNegotiator()
        assert n._negotiate_exports("GET", "https://api/profiles", ["x"]) is None

    def test_unknown_suffix_returns_none(self) -> None:
        n = ResourceTypeNegotiator()
        url = self._build_url("ZZZ")
        assert n._negotiate_exports("GET", url, ["application/json"]) is None

    def test_suffix_match_but_unavailable_type_returns_none(self) -> None:
        n = ResourceTypeNegotiator()
        url = self._build_url("C")
        # Suffix maps to campaignsexport but it's not in available_types
        assert n._negotiate_exports(
            "GET", url, ["application/json"]
        ) is None

    def test_export_id_without_comma_returns_none(self) -> None:
        n = ResourceTypeNegotiator()
        export_id = base64.urlsafe_b64encode(b"no-comma").decode().rstrip("=")
        url = f"https://api/exports/{export_id}"
        assert n._negotiate_exports("GET", url, ["application/json"]) is None


# --- ResourceTypeNegotiator.negotiate -------------------------------------


class TestNegotiate:
    def test_dispatches_to_registered_negotiator(self) -> None:
        n = ResourceTypeNegotiator()
        # exports negotiator is registered by default
        export_id = base64.urlsafe_b64encode(b"c-1,C").decode().rstrip("=")
        url = f"https://api/exports/{export_id}"
        result = n.negotiate(
            "GET", url, ["application/vnd.campaignsexport.v1+json"]
        )
        assert result == "application/vnd.campaignsexport.v1+json"

    def test_no_negotiator_for_resource_type_returns_none(self) -> None:
        n = ResourceTypeNegotiator()
        # 'profiles' has no registered negotiator
        assert n.negotiate("GET", "https://api/profiles/123", ["x"]) is None

    def test_exception_in_negotiator_returns_none(self) -> None:
        """A negotiator that raises must not break the call — log and
        return None so the caller falls back to first-listed."""
        n = ResourceTypeNegotiator()

        def explode(method: str, url: str, available: list) -> str:
            raise RuntimeError("boom")

        n.register_negotiator("explode", explode)
        assert n.negotiate("GET", "https://api/explode/1", ["x"]) is None

    def test_register_custom_negotiator(self) -> None:
        n = ResourceTypeNegotiator()

        def custom(method: str, url: str, available: list) -> str:
            return "application/custom+json"

        n.register_negotiator("custom", custom)
        assert n.negotiate(
            "GET", "https://api/custom/1", ["application/custom+json"]
        ) == "application/custom+json"


# --- EnhancedMediaTypeRegistry --------------------------------------------


class TestEnhancedMediaTypeRegistry:
    def test_delegates_to_base_when_single_accept(self) -> None:
        base = MagicMock()
        base.resolve = MagicMock(return_value=("application/json", ["application/json"]))
        registry = EnhancedMediaTypeRegistry(base)

        ct, accepts = registry.resolve("GET", "https://api/anything")
        # Single accept → no negotiation, base result returned untouched
        assert ct == "application/json"
        assert accepts == ["application/json"]

    def test_negotiates_when_multiple_accepts(self) -> None:
        base = MagicMock()
        base.resolve = MagicMock(return_value=(
            None,
            [
                "application/vnd.campaignsexport.v1+json",
                "application/vnd.adgroupsexport.v1+json",
            ],
        ))
        registry = EnhancedMediaTypeRegistry(base)

        export_id = base64.urlsafe_b64encode(b"c-1,C").decode().rstrip("=")
        url = f"https://api/exports/{export_id}"
        _, accepts = registry.resolve("GET", url)
        assert accepts == ["application/vnd.campaignsexport.v1+json"]

    def test_negotiation_miss_preserves_base_accepts(self) -> None:
        """If negotiation returns None, the base's accept list is preserved
        so the caller can still pick first-listed."""
        base = MagicMock()
        base.resolve = MagicMock(return_value=(
            None,
            ["application/json", "text/csv"],
        ))
        registry = EnhancedMediaTypeRegistry(base)

        # No registered negotiator for /unknown → no narrowing
        _, accepts = registry.resolve("GET", "https://api/unknown/1")
        assert accepts == ["application/json", "text/csv"]

    def test_add_negotiator_extends_registry(self) -> None:
        base = MagicMock()
        base.resolve = MagicMock(return_value=(None, ["a", "b"]))
        registry = EnhancedMediaTypeRegistry(base)

        registry.add_negotiator(
            "custom", lambda m, u, av: "a"
        )
        _, accepts = registry.resolve("GET", "https://api/custom/x")
        assert accepts == ["a"]


# --- create_enhanced_registry --------------------------------------------


class TestCreateEnhancedRegistry:
    def test_factory_returns_enhanced_registry(self) -> None:
        base = MagicMock()
        registry = create_enhanced_registry(base)
        assert isinstance(registry, EnhancedMediaTypeRegistry)
        assert registry.base_registry is base
