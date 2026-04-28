"""Round 13 B-8 — gold-master snapshot tests for SCHEMA_* envelopes.

Each snapshot file under ``schema_envelopes/<code>.json`` is the exact
``details``+``hints`` payload that ``SchemaValidationMiddleware``
produces for a known bad input. The test re-runs the bad input and
diffs the result against the on-disk gold master.

Why: the unit tests in ``test_schema_validation_hints.py`` assert
substring presence ("hint mentions the field path") — robust against
phrasing tweaks but blind to subtle drift. Production clients parse
specific phrasings (e.g. ``"Field {path} expected ..."``). A snapshot
test catches a one-word rename that the substring tests would miss
but a string parser would feel.

To intentionally update a snapshot, set ``UPDATE_SNAPSHOTS=1`` in the
environment — the test then writes the current payload over the gold
master rather than diffing.
"""

from __future__ import annotations

import json
import os
import pathlib

import pytest

from amazon_ads_mcp.exceptions import ValidationError as AdsValidationError
from amazon_ads_mcp.middleware.schema_validation import SchemaValidationMiddleware

SNAPSHOT_DIR = pathlib.Path(__file__).parent / "schema_envelopes"


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


def _force_strict_off(monkeypatch) -> None:
    from amazon_ads_mcp.middleware import schema_validation as sv_mod

    class _S:
        mcp_strict_unknown_fields = False

    monkeypatch.setattr(sv_mod, "settings", _S())


async def _capture_envelope_details(tool_schema: dict, args: dict) -> dict:
    """Run the middleware against (tool_schema, args), capture the
    raised exception's details payload (sorted keys for determinism)."""
    tool = _FakeTool(tool_schema)
    ctx = _FakeContext(tool)
    ctx.message = _FakeMessage("any_tool", args)
    mw = SchemaValidationMiddleware()

    async def _noop_call_next(c):
        return {"ok": True}

    try:
        await mw.on_call_tool(ctx, _noop_call_next)
    except AdsValidationError as exc:
        return {
            "code": exc.code,
            "details": exc.details,
        }
    raise AssertionError("middleware did not raise")


def _check_or_update_snapshot(name: str, payload: dict) -> None:
    """If ``UPDATE_SNAPSHOTS=1``, write ``payload`` to disk; otherwise
    compare against the on-disk gold master."""
    SNAPSHOT_DIR.mkdir(exist_ok=True)
    path = SNAPSHOT_DIR / f"{name}.json"
    serialized = json.dumps(payload, indent=2, sort_keys=True)
    if os.environ.get("UPDATE_SNAPSHOTS") == "1":
        path.write_text(serialized + "\n", encoding="utf-8")
        return
    if not path.exists():
        path.write_text(serialized + "\n", encoding="utf-8")
        pytest.skip(
            f"Snapshot {name}.json did not exist; created it. "
            f"Re-run to compare on subsequent invocations."
        )
    expected = path.read_text(encoding="utf-8").rstrip("\n")
    actual = serialized
    assert actual == expected, (
        f"Schema envelope snapshot drift for {name}.json. "
        f"Set UPDATE_SNAPSHOTS=1 to accept the new payload.\n"
        f"--- expected ---\n{expected}\n--- actual ---\n{actual}\n"
    )


# Test case table: (snapshot_name, schema, args, force_strict_off?)
SNAPSHOT_CASES = [
    (
        "SCHEMA_TYPE_MISMATCH",
        {
            "type": "object",
            "properties": {
                "marketplaceIds": {"type": "array", "items": {"type": "string"}},
            },
        },
        {"marketplaceIds": "not-an-array"},
        True,
    ),
    (
        "SCHEMA_MAX_ITEMS",
        {
            "type": "object",
            "properties": {
                "marketplaceIds": {
                    "type": "array",
                    "items": {"type": "string"},
                    "maxItems": 5,
                },
            },
        },
        {"marketplaceIds": ["a", "b", "c", "d", "e", "f"]},
        True,
    ),
    (
        "SCHEMA_REQUIRED",
        {
            "type": "object",
            "properties": {
                "marketplaceIds": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["marketplaceIds"],
        },
        {},
        True,
    ),
    (
        "SCHEMA_ENUM_MISMATCH",
        {
            "type": "object",
            "properties": {"region": {"type": "string", "enum": ["NA", "EU", "FE"]}},
        },
        {"region": "ASIA"},
        True,
    ),
    (
        "SCHEMA_ADDITIONAL_PROPERTIES",
        {
            "type": "object",
            "properties": {"primary": {"type": "string"}},
            "additionalProperties": False,
        },
        {"primary": "ok", "typo_key": 1},
        False,
    ),
]


@pytest.mark.parametrize(
    "name,schema,args,strict_off",
    SNAPSHOT_CASES,
    ids=[case[0] for case in SNAPSHOT_CASES],
)
@pytest.mark.asyncio
async def test_schema_envelope_snapshot(
    name: str, schema: dict, args: dict, strict_off: bool, monkeypatch
) -> None:
    if strict_off:
        _force_strict_off(monkeypatch)
    payload = await _capture_envelope_details(schema, args)
    _check_or_update_snapshot(name, payload)
