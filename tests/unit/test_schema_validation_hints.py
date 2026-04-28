"""Round 13 B-8 — hints[] populated on SCHEMA_* envelopes.

Phase 0a spike confirmed Ads emits SCHEMA_TYPE_MISMATCH with only a
generic boilerplate hint and no field-specific guidance. SCHEMA_REQUIRED
is partially populated. After B-8, EVERY SCHEMA_* code populates a
canonical-template-driven primary hint sourced from
``openbridge-mcp/schemas/jsonschema_error_codes.json``.

Tests cover:
  - Each canonical SCHEMA_* code produces a non-empty primary hint
    that mentions the relevant field path / limit / allowed values
  - Cache stability: ``_HINT_TEMPLATES`` is a frozen mapping
  - Cross-server parity (skipped when SP not in this venv)
"""

from __future__ import annotations

import pytest

from amazon_ads_mcp.exceptions import ValidationError as AdsValidationError
from amazon_ads_mcp.middleware.schema_validation import (
    _HINT_TEMPLATES,
    SchemaValidationMiddleware,
)


class _FakeTool:
    def __init__(self, parameters: dict) -> None:
        self.parameters = parameters


class _FakeFastMCP:
    def __init__(self, tool: _FakeTool) -> None:
        self._tool = tool

    async def get_tool(self, name: str):
        return self._tool


class _FakeContext:
    def __init__(self, tool: _FakeTool) -> None:
        self.fastmcp = _FakeFastMCP(tool)
        self.fastmcp_context = self
        self.message = None


class _FakeMessage:
    def __init__(self, name: str, arguments: dict) -> None:
        self.name = name
        self.arguments = arguments


def _make_context(tool: _FakeTool, name: str, args: dict) -> _FakeContext:
    ctx = _FakeContext(tool)
    ctx.message = _FakeMessage(name, args)
    return ctx


async def _noop_call_next(ctx) -> dict:
    return {"ok": True}


def _force_strict_off(monkeypatch) -> None:
    """Disable strict-unknown injection for type/required tests so
    additionalProperties:false isn't injected on ad-hoc schemas."""
    from amazon_ads_mcp.middleware import schema_validation as sv_mod

    class _S:
        mcp_strict_unknown_fields = False

    monkeypatch.setattr(sv_mod, "settings", _S())


# ---- Per-code hint coverage ---------------------------------------------


@pytest.mark.asyncio
async def test_type_mismatch_hint_mentions_field_path(monkeypatch) -> None:
    _force_strict_off(monkeypatch)
    tool = _FakeTool(
        {
            "type": "object",
            "properties": {
                "marketplaceIds": {"type": "array", "items": {"type": "string"}},
            },
        }
    )
    ctx = _make_context(tool, "any", {"marketplaceIds": "not-an-array"})
    mw = SchemaValidationMiddleware()
    with pytest.raises(AdsValidationError) as exc:
        await mw.on_call_tool(ctx, _noop_call_next)
    hints = exc.value.details.get("hints") or []
    assert hints, "SCHEMA_TYPE_MISMATCH must populate hints[]"
    joined = " ".join(hints)
    assert "marketplaceIds" in joined, (
        f"hint should reference the offending field path; got: {hints}"
    )


@pytest.mark.asyncio
async def test_max_items_hint_mentions_limit_and_field(monkeypatch) -> None:
    _force_strict_off(monkeypatch)
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
    ctx = _make_context(tool, "any", {"marketplaceIds": ["a"] * 6})
    mw = SchemaValidationMiddleware()
    with pytest.raises(AdsValidationError) as exc:
        await mw.on_call_tool(ctx, _noop_call_next)
    hints = exc.value.details.get("hints") or []
    joined = " ".join(hints)
    assert "marketplaceIds" in joined
    assert "5" in joined, f"hint should mention the maxItems limit; got: {hints}"


@pytest.mark.asyncio
async def test_required_hint_mentions_missing_field(monkeypatch) -> None:
    _force_strict_off(monkeypatch)
    tool = _FakeTool(
        {
            "type": "object",
            "properties": {
                "marketplaceIds": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["marketplaceIds"],
        }
    )
    ctx = _make_context(tool, "any", {})
    mw = SchemaValidationMiddleware()
    with pytest.raises(AdsValidationError) as exc:
        await mw.on_call_tool(ctx, _noop_call_next)
    hints = exc.value.details.get("hints") or []
    joined = " ".join(hints)
    assert "marketplaceIds" in joined


@pytest.mark.asyncio
async def test_enum_mismatch_hint_lists_allowed_values(monkeypatch) -> None:
    _force_strict_off(monkeypatch)
    tool = _FakeTool(
        {
            "type": "object",
            "properties": {"region": {"type": "string", "enum": ["NA", "EU", "FE"]}},
        }
    )
    ctx = _make_context(tool, "any", {"region": "ASIA"})
    mw = SchemaValidationMiddleware()
    with pytest.raises(AdsValidationError) as exc:
        await mw.on_call_tool(ctx, _noop_call_next)
    hints = exc.value.details.get("hints") or []
    joined = " ".join(hints)
    assert "region" in joined
    assert "NA" in joined and "EU" in joined and "FE" in joined, (
        f"enum hint must list allowed values; got: {hints}"
    )


@pytest.mark.asyncio
async def test_additional_properties_hint_mentions_extra_key() -> None:
    """additionalProperties: false rejection — strict mode default."""
    tool = _FakeTool(
        {
            "type": "object",
            "properties": {"primary": {"type": "string"}},
            "additionalProperties": False,
        }
    )
    ctx = _make_context(tool, "any", {"primary": "ok", "typo_key": 1})
    mw = SchemaValidationMiddleware()
    with pytest.raises(AdsValidationError) as exc:
        await mw.on_call_tool(ctx, _noop_call_next)
    hints = exc.value.details.get("hints") or []
    joined = " ".join(hints)
    assert "typo_key" in joined, (
        f"additionalProperties hint must name the offending key; got: {hints}"
    )


# ---- Cache stability -----------------------------------------------------


def test_hint_templates_is_frozen_mapping() -> None:
    """``_HINT_TEMPLATES`` is a ``MappingProxyType`` — mutation must
    raise. Catches a contributor who tries to update at runtime."""
    with pytest.raises(TypeError):
        _HINT_TEMPLATES["SCHEMA_TYPE_MISMATCH"] = {"hint": "x"}  # type: ignore[index]


def test_hint_templates_inner_dict_is_frozen() -> None:
    """The inner per-code dict is also frozen so a contributor can't
    swap one field of the template without going through the spec."""
    entry = _HINT_TEMPLATES.get("SCHEMA_TYPE_MISMATCH")
    if entry is None:
        pytest.skip("template spec not available in this checkout")
    with pytest.raises(TypeError):
        entry["hint"] = "tampered"  # type: ignore[index]


def test_hint_templates_loaded_keys_match_canonical() -> None:
    """The loaded templates should cover every canonical SCHEMA_*
    code from the static map, plus the fallback."""
    from amazon_ads_mcp.middleware.schema_validation import (
        ERROR_CODE_MAP,
        FALLBACK_CODE,
    )

    if not _HINT_TEMPLATES:
        pytest.skip("template spec not available in this checkout")
    canonical_codes = set(ERROR_CODE_MAP.values()) | {FALLBACK_CODE}
    loaded_codes = set(_HINT_TEMPLATES.keys())
    missing = canonical_codes - loaded_codes
    assert not missing, f"templates missing for codes: {missing}"


# ---- Cross-server parity -------------------------------------------------


def test_sp_and_ads_hint_templates_byte_identical() -> None:
    """Both servers MUST load the same template payload from the same
    spec file. Drift fails the conformance contract."""
    try:
        from amazon_sp_mcp.middleware.schema_validation import (
            _HINT_TEMPLATES as SP_TEMPLATES,
        )
    except ImportError:
        pytest.skip("amazon_sp_mcp not available in this venv")

    if not _HINT_TEMPLATES or not SP_TEMPLATES:
        pytest.skip("template spec not available in this checkout")

    assert dict(_HINT_TEMPLATES) == dict(SP_TEMPLATES), (
        "SP and Ads loaded different hint-template payloads — "
        "spec-file resolution paths must agree."
    )
