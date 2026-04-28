"""Round 13 Phase C-1 — `mode="validate_body"` + deprecated-shape hints.

Closes client finding 3: top-level `name`/`configuration`/`query` keys
on AdsApiv1CreateReport are deprecated v3 shapes that look plausible
because they appear in older tutorials. The schema validator's
generic "Remove unknown key" hint isn't actionable; a curated
"v3 tutorial" attribution closes the loop.

Pinned contract:
  - `mode="validate_body"` accepts a `body` arg, validates against
    the runtime CreateReport schema (single source of truth — same
    object the live tool uses).
  - Returns `{shape_errors[], unknown_fields[], missing_required{},
    suggested_replacements{}, deprecated_shape_hints[]}`.
  - `DEPRECATED_V1_SHAPE_KEYS` table provides curated rationale +
    "v3 tutorial" attribution for the three known bad top-level keys.
  - Wired into both `validate_body` AND
    `schema_validation.SchemaValidationMiddleware`'s SCHEMA_*
    additionalProperties hint enricher (so live runtime calls also
    get the curated hint, not just pre-flight validation).
"""

from __future__ import annotations

import pytest

from amazon_ads_mcp.tools.report_fields_v1_handler import (
    DEPRECATED_V1_SHAPE_KEYS,
    handle as report_fields_handle,
    ReportFieldsToolError,
)


# ---- DEPRECATED_V1_SHAPE_KEYS table shape ------------------------------


def test_deprecated_v1_shape_table_covers_three_known_keys() -> None:
    required = {"name", "configuration", "query"}
    missing = required - set(DEPRECATED_V1_SHAPE_KEYS.keys())
    assert not missing, f"DEPRECATED_V1_SHAPE_KEYS missing: {missing}"


def test_deprecated_shape_hints_attribute_v3_tutorial_origin() -> None:
    """The error-message-as-tutor pattern: every deprecated-shape
    hint MUST mention v3 (or 'tutorial' / earlier API generations) so
    the agent learns WHY the key looked plausible — not just that
    it's wrong."""
    for key, hint in DEPRECATED_V1_SHAPE_KEYS.items():
        assert isinstance(hint, str) and hint
        hint_lower = hint.lower()
        assert "v3" in hint_lower or "tutorial" in hint_lower, (
            f"deprecated-shape hint for {key!r} must attribute origin "
            f"(v3 / tutorial); got: {hint}"
        )


def test_deprecated_shape_hints_show_correct_replacement_path() -> None:
    """Each hint must point at the correct v1 path so the agent can
    rewrite the request, not just delete the key."""
    name_hint = DEPRECATED_V1_SHAPE_KEYS["name"]
    assert "reports[" in name_hint  # nests under reports[*]
    cfg_hint = DEPRECATED_V1_SHAPE_KEYS["configuration"]
    assert "format" in cfg_hint and "periods" in cfg_hint
    q_hint = DEPRECATED_V1_SHAPE_KEYS["query"]
    assert "reports[" in q_hint and "query" in q_hint


# ---- mode="validate_body" handler ---------------------------------------


def _ok_body() -> dict:
    """Minimum valid CreateReport body (single source of truth: the
    runtime schema. If this body stops validating, the runtime schema
    drifted and we'd want to know.)"""
    return {
        "accessRequestedAccounts": [
            {"advertiserAccountId": "amzn1.ads-account.g.placeholder"}
        ],
        "reports": [
            {
                "format": "GZIP_JSON",
                "periods": [
                    {
                        "datePeriod": {
                            "startDate": "2026-04-01",
                            "endDate": "2026-04-07",
                        }
                    }
                ],
                "query": {"fields": ["metric.totalCost", "campaign.id"]},
            }
        ],
    }


def test_validate_body_accepts_canonical_body() -> None:
    result = report_fields_handle(
        mode="validate_body",
        operation="allv1_AdsApiv1CreateReport",
        body=_ok_body(),
    )
    payload = result.model_dump(exclude_none=True)
    assert payload.get("valid") is True
    assert payload.get("shape_errors", []) == []
    assert payload.get("deprecated_shape_hints", []) == []


def test_validate_body_flags_top_level_name() -> None:
    """Client finding 3: `name` at the top level is a v3 shape.
    validate_body must surface it as a deprecated-shape hint with
    v3-tutorial attribution."""
    bad = {
        "accessRequestedAccounts": [{"advertiserAccountId": "x"}],
        "name": "this is a v3 shape",
        "reports": [],
    }
    result = report_fields_handle(
        mode="validate_body",
        operation="allv1_AdsApiv1CreateReport",
        body=bad,
    )
    payload = result.model_dump(exclude_none=True)
    assert payload.get("valid") is False
    deprecated = payload.get("deprecated_shape_hints") or []
    assert deprecated, "deprecated_shape_hints must surface 'name'"
    joined = " ".join(str(h) for h in deprecated)
    assert "name" in joined
    assert "v3" in joined.lower() or "tutorial" in joined.lower()
    assert "reports[" in joined  # tells agent where to nest the report


def test_validate_body_flags_top_level_configuration() -> None:
    bad = {
        "accessRequestedAccounts": [{"advertiserAccountId": "x"}],
        "configuration": {"format": "GZIP_JSON"},
        "reports": [],
    }
    result = report_fields_handle(
        mode="validate_body",
        operation="allv1_AdsApiv1CreateReport",
        body=bad,
    )
    payload = result.model_dump(exclude_none=True)
    deprecated = payload.get("deprecated_shape_hints") or []
    joined = " ".join(str(h) for h in deprecated)
    assert "configuration" in joined
    assert "format" in joined  # points to the right v1 location


def test_validate_body_flags_top_level_query() -> None:
    bad = {
        "accessRequestedAccounts": [{"advertiserAccountId": "x"}],
        "query": {"fields": ["metric.totalCost"]},
        "reports": [],
    }
    result = report_fields_handle(
        mode="validate_body",
        operation="allv1_AdsApiv1CreateReport",
        body=bad,
    )
    payload = result.model_dump(exclude_none=True)
    deprecated = payload.get("deprecated_shape_hints") or []
    joined = " ".join(str(h) for h in deprecated)
    assert "query" in joined
    assert "reports[" in joined


def test_validate_body_missing_body_arg_rejected() -> None:
    with pytest.raises(ReportFieldsToolError) as exc:
        report_fields_handle(
            mode="validate_body",
            operation="allv1_AdsApiv1CreateReport",
        )
    assert exc.value.code == "INVALID_MODE_ARGS"


def test_validate_body_with_query_mode_arg_rejected() -> None:
    """Cross-mode args still rejected so validate_body stays a pure
    body-shape validator."""
    with pytest.raises(ReportFieldsToolError) as exc:
        report_fields_handle(
            mode="validate_body",
            operation="allv1_AdsApiv1CreateReport",
            body=_ok_body(),
            search="cost",
        )
    assert exc.value.code == "INVALID_MODE_ARGS"


def test_validate_body_with_validate_fields_rejected() -> None:
    """validate_fields belongs to mode='validate', not validate_body."""
    with pytest.raises(ReportFieldsToolError) as exc:
        report_fields_handle(
            mode="validate_body",
            operation="allv1_AdsApiv1CreateReport",
            body=_ok_body(),
            validate_fields=["metric.clicks"],
        )
    assert exc.value.code == "INVALID_MODE_ARGS"


# ---- runtime middleware hint enricher (live SCHEMA_ADDITIONAL_PROPERTIES)


@pytest.mark.asyncio
async def test_schema_validation_middleware_handles_multiple_extras_simultaneously() -> None:
    """Round 13 follow-up — when jsonschema reports MULTIPLE extra
    keys in one error (``'configuration', 'name', 'query' were
    unexpected`` — plural ``were``), the previous regex matched
    singular only, so ``details.extra`` was empty AND the deprecated-
    shape lookup keyed off an empty string. The visible bug surfaced
    on the wire as ``"Remove unknown key  or check schema for typos."``
    (double space) plus no v3-tutorial attribution.

    Now: every offending key gets its own deprecated-shape hint when
    matched, AND ``details.extra`` carries the first key for
    backward compatibility."""
    from amazon_ads_mcp.exceptions import ValidationError as AdsValidationError
    from amazon_ads_mcp.middleware.schema_validation import (
        SchemaValidationMiddleware,
    )
    from unittest.mock import MagicMock

    class _Tool:
        parameters = {
            "type": "object",
            "properties": {
                "accessRequestedAccounts": {"type": "array"},
                "reports": {"type": "array"},
            },
            "required": ["accessRequestedAccounts"],
        }

    class _FastMCP:
        async def get_tool(self, name):
            return _Tool()

    class _Ctx:
        def __init__(self):
            self.fastmcp = _FastMCP()
            self.fastmcp_context = self
            self.message = MagicMock()
            self.message.name = "allv1_AdsApiv1CreateReport"
            # All three v3-shape keys at once — triggers plural form
            # ``were unexpected``.
            self.message.arguments = {
                "accessRequestedAccounts": [{"advertiserAccountId": "x"}],
                "name": "from a v3 tutorial",
                "configuration": {"format": "GZIP_JSON"},
                "query": {"fields": ["metric.totalCost"]},
            }

    mw = SchemaValidationMiddleware()

    async def call_next(c):
        return {"ok": True}

    with pytest.raises(AdsValidationError) as exc:
        await mw.on_call_tool(_Ctx(), call_next)
    hints = exc.value.details.get("hints") or []
    joined = " ".join(hints)
    # Each of the three v3-shape keys must produce its own
    # attributed hint. Previously: zero hints (extra was empty).
    assert "name" in joined and "configuration" in joined and "query" in joined.lower(), (
        f"all three v3-shape keys must surface in hints; got: {hints}"
    )
    # v3-tutorial attribution must appear (compounding-tutor pattern).
    assert "v3" in joined.lower() or "tutorial" in joined.lower()
    # The double-space "Remove unknown key  or" bug must be fixed —
    # ``details.extra`` must carry at least the first offending key.
    extra = exc.value.details.get("extra")
    assert extra in ("name", "configuration", "query"), (
        f"details.extra must carry one of the offending keys; got: {extra!r}"
    )


@pytest.mark.asyncio
async def test_schema_validation_middleware_uses_deprecated_shape_hint(
    monkeypatch,
) -> None:
    """When SchemaValidationMiddleware rejects `name` at the top level
    of a CreateReport call (live, not just pre-flight), the hint
    should reference the deprecated-shape table — not just the generic
    'Did you mean' from the catalog."""
    from amazon_ads_mcp.exceptions import ValidationError as AdsValidationError
    from amazon_ads_mcp.middleware.schema_validation import (
        SchemaValidationMiddleware,
    )
    from unittest.mock import MagicMock

    # Mock CreateReport tool — schema mirrors the real one's top level
    # (additionalProperties: false enforced by Round 12 strict default).
    class _Tool:
        parameters = {
            "type": "object",
            "properties": {
                "accessRequestedAccounts": {"type": "array"},
                "reports": {"type": "array"},
            },
            "required": ["accessRequestedAccounts"],
        }

    class _FastMCP:
        async def get_tool(self, name):
            return _Tool()

    class _Ctx:
        def __init__(self):
            self.fastmcp = _FastMCP()
            self.fastmcp_context = self
            self.message = MagicMock()
            self.message.name = "allv1_AdsApiv1CreateReport"
            self.message.arguments = {
                "accessRequestedAccounts": [{"advertiserAccountId": "x"}],
                "name": "this is a v3 shape",
            }

    mw = SchemaValidationMiddleware()

    async def call_next(c):
        return {"ok": True}

    with pytest.raises(AdsValidationError) as exc:
        await mw.on_call_tool(_Ctx(), call_next)
    hints = exc.value.details.get("hints") or []
    joined = " ".join(hints)
    assert "v3" in joined.lower() or "tutorial" in joined.lower(), (
        f"runtime hint for top-level 'name' on CreateReport must "
        f"attribute v3 origin; got: {hints}"
    )
    assert "reports[" in joined, (
        f"hint must show the correct v1 nesting; got: {hints}"
    )
