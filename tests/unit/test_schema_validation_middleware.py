"""Phase 1 — pre-flight JSON Schema validation middleware tests (Ads parity).

Mirror of ``amazon_sp_mcp/tests/unit/test_schema_validation_middleware.py``.
Both servers must emit identical envelope ``error_code`` strings for the
same schema-violation shape. The conformance scaffold in openbridge-mcp
asserts this property end-to-end via live MCP probes.
"""

from __future__ import annotations

from typing import Any

import pytest

from amazon_ads_mcp.exceptions import ValidationError as AdsValidationError
from amazon_ads_mcp.middleware.schema_validation import (
    SchemaValidationMiddleware,
)


class _FakeTool:
    def __init__(self, parameters: dict) -> None:
        self.parameters = parameters


class _FakeFastMCP:
    def __init__(self, tool: _FakeTool | None) -> None:
        self._tool = tool

    async def get_tool(self, name: str) -> _FakeTool | None:
        return self._tool


class _FakeContext:
    def __init__(self, tool: _FakeTool | None) -> None:
        self.fastmcp = _FakeFastMCP(tool)
        self.fastmcp_context = self
        self.message: Any = None


class _FakeMessage:
    def __init__(self, name: str, arguments: dict) -> None:
        self.name = name
        self.arguments = arguments


def _make_context(tool: _FakeTool | None, name: str, args: dict) -> _FakeContext:
    ctx = _FakeContext(tool)
    ctx.message = _FakeMessage(name, args)
    return ctx


async def _noop_call_next(ctx: _FakeContext) -> dict:
    return {"ok": True}


class TestFlatFieldValidation:
    @pytest.mark.asyncio
    async def test_string_for_array_raises_type_mismatch(self) -> None:
        tool = _FakeTool(
            {
                "type": "object",
                "properties": {
                    "marketplaceIds": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                },
                "additionalProperties": False,
            }
        )
        ctx = _make_context(tool, "any_tool", {"marketplaceIds": "ATVPDKIKX0DER"})
        mw = SchemaValidationMiddleware()
        with pytest.raises(AdsValidationError) as exc:
            await mw.on_call_tool(ctx, _noop_call_next)
        assert exc.value.code == "SCHEMA_TYPE_MISMATCH"
        assert exc.value.details.get("field") == "marketplaceIds"

    @pytest.mark.asyncio
    async def test_max_items_exceeded_raises(self) -> None:
        tool = _FakeTool(
            {
                "type": "object",
                "properties": {
                    "marketplaceIds": {
                        "type": "array",
                        "items": {"type": "string"},
                        "maxItems": 5,
                    },
                },
            }
        )
        ctx = _make_context(
            tool, "any_tool", {"marketplaceIds": ["a", "b", "c", "d", "e", "f"]}
        )
        mw = SchemaValidationMiddleware()
        with pytest.raises(AdsValidationError) as exc:
            await mw.on_call_tool(ctx, _noop_call_next)
        assert exc.value.code == "SCHEMA_MAX_ITEMS"
        assert exc.value.details.get("limit") == 5
        assert exc.value.details.get("actual") == 6

    @pytest.mark.asyncio
    async def test_required_field_missing_raises(self) -> None:
        tool = _FakeTool(
            {
                "type": "object",
                "properties": {
                    "marketplaceIds": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["marketplaceIds"],
            }
        )
        ctx = _make_context(tool, "any_tool", {})
        mw = SchemaValidationMiddleware()
        with pytest.raises(AdsValidationError) as exc:
            await mw.on_call_tool(ctx, _noop_call_next)
        assert exc.value.code == "SCHEMA_REQUIRED"
        assert exc.value.details.get("field") == "marketplaceIds"

    @pytest.mark.asyncio
    async def test_enum_mismatch_raises(self) -> None:
        tool = _FakeTool(
            {
                "type": "object",
                "properties": {
                    "region": {
                        "type": "string",
                        "enum": ["NA", "EU", "FE"],
                    },
                },
            }
        )
        ctx = _make_context(tool, "set_region", {"region": "ASIA"})
        mw = SchemaValidationMiddleware()
        with pytest.raises(AdsValidationError) as exc:
            await mw.on_call_tool(ctx, _noop_call_next)
        assert exc.value.code == "SCHEMA_ENUM_MISMATCH"
        assert "NA" in (exc.value.details.get("allowed") or [])


class TestNestedAndCombinatorValidation:
    @pytest.mark.asyncio
    async def test_nested_type_mismatch_carries_pointer_path(self) -> None:
        tool = _FakeTool(
            {
                "type": "object",
                "properties": {
                    "filters": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "marketplaceId": {"type": "string"},
                            },
                        },
                    },
                },
            }
        )
        ctx = _make_context(
            tool, "any_tool", {"filters": [{"marketplaceId": 12345}]}
        )
        mw = SchemaValidationMiddleware()
        with pytest.raises(AdsValidationError) as exc:
            await mw.on_call_tool(ctx, _noop_call_next)
        assert exc.value.code == "SCHEMA_TYPE_MISMATCH"
        assert exc.value.details.get("field") == "filters/0/marketplaceId"

    @pytest.mark.asyncio
    async def test_additional_properties_on_nested_object(self) -> None:
        tool = _FakeTool(
            {
                "type": "object",
                "properties": {
                    "options": {
                        "type": "object",
                        "properties": {
                            "verbose": {"type": "boolean"},
                        },
                        "additionalProperties": False,
                    },
                },
            }
        )
        ctx = _make_context(
            tool, "any_tool", {"options": {"verbose": True, "unexpected": 42}}
        )
        mw = SchemaValidationMiddleware()
        with pytest.raises(AdsValidationError) as exc:
            await mw.on_call_tool(ctx, _noop_call_next)
        assert exc.value.code == "SCHEMA_ADDITIONAL_PROPERTIES"
        assert exc.value.details.get("extra") == "unexpected"

    @pytest.mark.asyncio
    async def test_one_of_no_match_raises(self) -> None:
        tool = _FakeTool(
            {
                "type": "object",
                "properties": {
                    "payload": {
                        "oneOf": [
                            {"type": "string"},
                            {"type": "integer"},
                        ],
                    },
                },
            }
        )
        ctx = _make_context(tool, "any_tool", {"payload": [1, 2, 3]})
        mw = SchemaValidationMiddleware()
        with pytest.raises(AdsValidationError) as exc:
            await mw.on_call_tool(ctx, _noop_call_next)
        assert exc.value.code == "SCHEMA_ONE_OF_FAILED"
        assert exc.value.details.get("field") == "payload"


class TestPassThrough:
    @pytest.mark.asyncio
    async def test_valid_args_dispatch_without_error(self) -> None:
        tool = _FakeTool(
            {
                "type": "object",
                "properties": {
                    "marketplaceIds": {
                        "type": "array",
                        "items": {"type": "string"},
                        "maxItems": 5,
                    },
                },
            }
        )
        ctx = _make_context(tool, "any_tool", {"marketplaceIds": ["A"]})
        mw = SchemaValidationMiddleware()
        result = await mw.on_call_tool(ctx, _noop_call_next)
        assert result == {"ok": True}

    @pytest.mark.asyncio
    async def test_empty_parameters_no_op(self) -> None:
        tool = _FakeTool({"type": "object", "properties": {}})
        ctx = _make_context(tool, "tool_with_no_declared_params", {"anything": 1})
        mw = SchemaValidationMiddleware()
        result = await mw.on_call_tool(ctx, _noop_call_next)
        assert result == {"ok": True}

    @pytest.mark.asyncio
    async def test_no_tool_resolved_no_op(self) -> None:
        ctx = _make_context(None, "missing_tool", {"x": 1})
        mw = SchemaValidationMiddleware()
        result = await mw.on_call_tool(ctx, _noop_call_next)
        assert result == {"ok": True}


class TestStrictUnknownFields:
    """Round 12 SP-7 (Ads parity): MCP_STRICT_UNKNOWN_FIELDS injection in
    ``SchemaValidationMiddleware``. Ads also has an independent
    ``check_strict_unknown_fields`` layer in ``schema_normalization.py``;
    both layers fail fast on unknown fields with
    ``error_kind=mcp_input_validation`` envelopes."""

    @pytest.mark.asyncio
    async def test_flag_on_silent_schema_rejects_unknown_field(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from amazon_ads_mcp.middleware import schema_validation as sv_mod

        class _FakeSettings:
            mcp_strict_unknown_fields = True

        monkeypatch.setattr(sv_mod, "settings", _FakeSettings())
        tool = _FakeTool(
            {
                "type": "object",
                "properties": {
                    "marketplaceIds": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                },
            }
        )
        ctx = _make_context(
            tool, "any_tool", {"marketplaceIds": ["A"], "typo_field": 1}
        )
        mw = SchemaValidationMiddleware()
        with pytest.raises(AdsValidationError) as exc:
            await mw.on_call_tool(ctx, _noop_call_next)
        assert exc.value.code == "SCHEMA_ADDITIONAL_PROPERTIES"
        assert exc.value.details.get("extra") == "typo_field"

    @pytest.mark.asyncio
    async def test_flag_off_silent_schema_passes_through(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Patch the BOUND name in the middleware module — other tests in
        # the suite rebind settings via monkeypatch.setattr on individual
        # modules, so reaching into the source-singleton's attr alone
        # isn't reliable in full-suite ordering.
        from amazon_ads_mcp.middleware import schema_validation as sv_mod

        class _FakeSettings:
            mcp_strict_unknown_fields = False

        monkeypatch.setattr(sv_mod, "settings", _FakeSettings())
        tool = _FakeTool(
            {
                "type": "object",
                "properties": {
                    "marketplaceIds": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                },
            }
        )
        ctx = _make_context(
            tool, "any_tool", {"marketplaceIds": ["A"], "typo_field": 1}
        )
        mw = SchemaValidationMiddleware()
        result = await mw.on_call_tool(ctx, _noop_call_next)
        assert result == {"ok": True}

    @pytest.mark.asyncio
    async def test_flag_on_explicit_additional_properties_true_respected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from amazon_ads_mcp.middleware import schema_validation as sv_mod

        class _FakeSettings:
            mcp_strict_unknown_fields = True

        monkeypatch.setattr(sv_mod, "settings", _FakeSettings())
        tool = _FakeTool(
            {
                "type": "object",
                "properties": {
                    "marketplaceIds": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                },
                "additionalProperties": True,
            }
        )
        ctx = _make_context(
            tool, "any_tool", {"marketplaceIds": ["A"], "extra_allowed": 1}
        )
        mw = SchemaValidationMiddleware()
        result = await mw.on_call_tool(ctx, _noop_call_next)
        assert result == {"ok": True}


class TestCanonicalMappingAlignment:
    """Asserts the Ads middleware's error_code values match the canonical
    spec at openbridge-mcp/schemas/jsonschema_error_codes.json."""

    @pytest.mark.asyncio
    async def test_codes_are_from_canonical_set(self) -> None:
        from amazon_ads_mcp.middleware.schema_validation import (
            ERROR_CODE_MAP,
            FALLBACK_CODE,
        )
        for validator, code in ERROR_CODE_MAP.items():
            assert isinstance(code, str) and code.startswith("SCHEMA_"), (
                f"validator {validator!r} mapped to non-canonical code {code!r}"
            )
        assert FALLBACK_CODE == "SCHEMA_VALIDATION_FAILED"

    @pytest.mark.asyncio
    async def test_sp_and_ads_maps_byte_identical(self) -> None:
        """Cross-server parity: SP and Ads must agree on every entry."""
        from amazon_ads_mcp.middleware.schema_validation import (
            ERROR_CODE_MAP as ADS_MAP,
            FALLBACK_CODE as ADS_FB,
        )
        try:
            from amazon_sp_mcp.middleware.schema_validation import (
                ERROR_CODE_MAP as SP_MAP,
                FALLBACK_CODE as SP_FB,
            )
        except ImportError:
            pytest.skip("amazon_sp_mcp not available in this venv")
        assert ADS_MAP == SP_MAP, "Cross-server canonical mapping drift"
        assert ADS_FB == SP_FB, "Cross-server fallback drift"
