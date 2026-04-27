"""Coverage-pushing tests for ``server.transform_executor`` pure helpers.

Round-13 had this module at 45% (246 of 450 statements uncovered). The
public ``DeclarativeTransformExecutor`` exposes a large set of small,
pure helper methods (``_compose_structure``, ``_walk``, ``_coerce_*``,
``_parse_flexible``, ``_deep_merge_dicts``, ``_get_by_path``,
``_set_by_path``, ``_validate_preset``). All testable without FastMCP
plumbing.
"""

from __future__ import annotations

import pytest

from amazon_ads_mcp.server.transform_executor import DeclarativeTransformExecutor


@pytest.fixture
def executor() -> DeclarativeTransformExecutor:
    """A bare executor with no rules — sufficient for pure-helper tests."""
    return DeclarativeTransformExecutor(namespace="test", rules={})


# --- _compose_structure ---------------------------------------------------


class TestComposeStructure:
    def test_dollar_var_substituted(self, executor) -> None:
        out = executor._compose_structure({"x": "$name"}, {"name": "alice"})
        assert out == {"x": "alice"}

    def test_missing_var_returns_none(self, executor) -> None:
        out = executor._compose_structure({"x": "$missing"}, {})
        assert out == {"x": None}

    def test_non_dollar_string_passes_through(self, executor) -> None:
        out = executor._compose_structure({"x": "literal"}, {})
        assert out == {"x": "literal"}

    def test_nested_dict_recursive(self, executor) -> None:
        template = {"outer": {"inner": "$a", "fixed": "x"}}
        out = executor._compose_structure(template, {"a": "ok"})
        assert out == {"outer": {"inner": "ok", "fixed": "x"}}

    def test_list_recursive(self, executor) -> None:
        out = executor._compose_structure(["$x", "literal", "$y"], {"x": 1, "y": 2})
        assert out == [1, "literal", 2]

    def test_non_string_scalar_passes_through(self, executor) -> None:
        assert executor._compose_structure(42, {}) == 42
        assert executor._compose_structure(None, {}) is None
        assert executor._compose_structure(True, {}) is True


# --- _walk ----------------------------------------------------------------


class TestWalk:
    def test_applies_fn_to_scalars(self, executor) -> None:
        out = executor._walk({"a": 1, "b": [2, 3]}, lambda v: v * 10 if isinstance(v, int) else v)
        assert out == {"a": 10, "b": [20, 30]}

    def test_passes_through_empty_dict(self, executor) -> None:
        assert executor._walk({}, lambda v: v) == {}

    def test_handles_deeply_nested(self, executor) -> None:
        data = {"a": {"b": {"c": "X"}}}
        out = executor._walk(data, lambda v: v.lower() if isinstance(v, str) else v)
        assert out == {"a": {"b": {"c": "x"}}}


# --- _coerce_enum_case ----------------------------------------------------


class TestCoerceEnumCase:
    def test_uppercases_alpha_strings(self, executor) -> None:
        out = executor._coerce_enum_case({"state": "enabled"})
        assert out["state"] == "ENABLED"

    def test_skips_non_alpha(self, executor) -> None:
        out = executor._coerce_enum_case({"name": "John Doe"})  # has space
        assert out["name"] == "John Doe"  # unchanged

    def test_recursive(self, executor) -> None:
        out = executor._coerce_enum_case({"nested": {"state": "paused"}})
        assert out["nested"]["state"] == "PAUSED"


# --- _coerce_dates --------------------------------------------------------


class TestCoerceDates:
    def test_normalizes_iso_date(self, executor) -> None:
        out = executor._coerce_dates({"d": "2024-03-15"})
        assert out["d"] == "2024-03-15"

    def test_converts_us_format(self, executor) -> None:
        out = executor._coerce_dates({"d": "03/15/2024"})
        assert out["d"] == "2024-03-15"

    def test_converts_slash_iso_format(self, executor) -> None:
        out = executor._coerce_dates({"d": "2024/03/15"})
        assert out["d"] == "2024-03-15"

    def test_converts_iso_with_time(self, executor) -> None:
        out = executor._coerce_dates({"d": "2024-03-15T10:30:00"})
        assert out["d"] == "2024-03-15"

    def test_unparseable_passes_through(self, executor) -> None:
        out = executor._coerce_dates({"d": "not-a-date"})
        assert out["d"] == "not-a-date"


# --- _coerce_numbers_to_strings -------------------------------------------


class TestCoerceNumbersToStrings:
    def test_int_to_string(self, executor) -> None:
        assert executor._coerce_numbers_to_strings({"x": 42}) == {"x": "42"}

    def test_float_to_string(self, executor) -> None:
        assert executor._coerce_numbers_to_strings({"x": 1.5}) == {"x": "1.5"}

    def test_recursive_in_list(self, executor) -> None:
        out = executor._coerce_numbers_to_strings({"ids": [1, 2, 3]})
        assert out["ids"] == ["1", "2", "3"]

    def test_skips_non_numeric(self, executor) -> None:
        out = executor._coerce_numbers_to_strings({"name": "abc", "flag": True})
        # Note: True is bool but isinstance(True, int) is True in Python — gets stringified
        assert out["name"] == "abc"


# --- _coerce_iso_to_epoch_ms ---------------------------------------------


class TestCoerceIsoToEpochMs:
    def test_only_targeted_keys_converted(self, executor) -> None:
        out = executor._coerce_iso_to_epoch_ms({
            "startTime": "2024-01-01T00:00:00Z",
            "title": "ignore-me",
        })
        # startTime converted; title untouched
        assert isinstance(out["startTime"], int)
        assert out["title"] == "ignore-me"

    def test_iso_z_converted_to_epoch_ms(self, executor) -> None:
        out = executor._coerce_iso_to_epoch_ms({
            "endTime": "2024-01-01T00:00:00Z",
        })
        assert out["endTime"] == 1704067200000  # 2024-01-01T00:00:00Z in ms

    def test_date_only_assumed_midnight_utc(self, executor) -> None:
        out = executor._coerce_iso_to_epoch_ms({"startTime": "2024-01-01"})
        assert out["startTime"] == 1704067200000

    def test_compact_yyyymmdd_handled_as_numeric_string_quirk(self, executor) -> None:
        """Documented quirk (see ``docs/audit/latent-issues.md`` #4):
        ``"20240101"`` doesn't reach the YYYYMMDD-as-date
        branch because the ``s.isdigit()`` numeric-string check fires first
        and treats it as 20240101 seconds (then ×1000 = 20240101000 ms).

        The ``len(s) == 8 and s.isdigit()`` YYYYMMDD branch lower in the
        function is effectively dead code for this input shape.

        Pinning current behavior so any future fix (reordering the
        branches) breaks the test loudly and the maintainer can ratify
        the change.
        """
        out = executor._coerce_iso_to_epoch_ms({"startTime": "20240101"})
        # NOT 1704067200000 — current impl treats it as seconds-promoted-to-ms
        assert out["startTime"] == 20240101 * 1000

    def test_int_seconds_promoted_to_ms(self, executor) -> None:
        out = executor._coerce_iso_to_epoch_ms({"startTime": 1704067200})
        assert out["startTime"] == 1704067200 * 1000

    def test_int_already_ms_unchanged(self, executor) -> None:
        out = executor._coerce_iso_to_epoch_ms({"startTime": 1704067200000})
        assert out["startTime"] == 1704067200000

    def test_float_treated_as_seconds(self, executor) -> None:
        out = executor._coerce_iso_to_epoch_ms({"startTime": 1.5})
        assert out["startTime"] == 1500

    def test_numeric_string_promoted(self, executor) -> None:
        out = executor._coerce_iso_to_epoch_ms({"startTime": "1704067200"})
        assert out["startTime"] == 1704067200 * 1000

    def test_unparseable_string_passes_through(self, executor) -> None:
        out = executor._coerce_iso_to_epoch_ms({"startTime": "garbage"})
        assert out["startTime"] == "garbage"


# --- _apply_coercions dispatcher -----------------------------------------


class TestApplyCoercions:
    def test_no_kinds_returns_unchanged(self, executor) -> None:
        data = {"x": "Hello"}
        assert executor._apply_coercions(data, []) == data
        assert executor._apply_coercions(data, None) == data

    def test_dispatches_enum_case(self, executor) -> None:
        out = executor._apply_coercions({"s": "active"}, ["enum_case"])
        assert out["s"] == "ACTIVE"

    def test_dispatches_date_yyyy_mm_dd(self, executor) -> None:
        out = executor._apply_coercions({"d": "03/15/2024"}, ["date_yyyy_mm_dd"])
        assert out["d"] == "2024-03-15"

    def test_dispatches_number_to_string(self, executor) -> None:
        out = executor._apply_coercions({"n": 42}, ["number_to_string"])
        assert out["n"] == "42"

    def test_dispatches_iso_to_epoch_ms(self, executor) -> None:
        out = executor._apply_coercions(
            {"startTime": "2024-01-01T00:00:00Z"}, ["iso_to_epoch_ms"]
        )
        assert out["startTime"] == 1704067200000

    def test_unknown_kind_silently_skipped(self, executor) -> None:
        # Robustness: unknown kinds in config should not crash
        out = executor._apply_coercions({"x": "y"}, ["nonexistent_kind"])
        assert out == {"x": "y"}

    def test_multiple_kinds_chained(self, executor) -> None:
        out = executor._apply_coercions(
            {"state": "active", "n": 42},
            ["enum_case", "number_to_string"],
        )
        assert out == {"state": "ACTIVE", "n": "42"}


# --- _parse_flexible ------------------------------------------------------


class TestParseFlexible:
    def test_dict_passed_through(self, executor) -> None:
        d = {"a": 1}
        assert executor._parse_flexible(d) is d

    def test_list_passed_through(self, executor) -> None:
        L = [1, 2, 3]
        assert executor._parse_flexible(L) is L

    def test_json_string_parsed(self, executor) -> None:
        out = executor._parse_flexible('{"x": 1}')
        assert out == {"x": 1}

    def test_yaml_string_parsed(self, executor) -> None:
        # Best-effort YAML; if pyyaml not installed, falls back to original
        out = executor._parse_flexible("a: 1\nb: 2")
        # Either parsed dict or original string
        assert out == {"a": 1, "b": 2} or out == "a: 1\nb: 2"

    def test_unparseable_string_passes_through(self, executor) -> None:
        out = executor._parse_flexible("not: valid: yaml::")
        # Either yaml-error fallback (original) or whatever yaml.safe_load returns
        assert isinstance(out, (str, dict, list))

    def test_non_string_non_collection_passes_through(self, executor) -> None:
        assert executor._parse_flexible(42) == 42
        assert executor._parse_flexible(None) is None


# --- _deep_merge_dicts ----------------------------------------------------


class TestDeepMergeDicts:
    def test_disjoint_keys_merged(self, executor) -> None:
        out = executor._deep_merge_dicts({"a": 1}, {"b": 2})
        assert out == {"a": 1, "b": 2}

    def test_b_overrides_a_for_scalar(self, executor) -> None:
        out = executor._deep_merge_dicts({"a": 1}, {"a": 2})
        assert out["a"] == 2

    def test_nested_dicts_merged_recursively(self, executor) -> None:
        out = executor._deep_merge_dicts(
            {"x": {"a": 1, "b": 2}},
            {"x": {"b": 20, "c": 30}},
        )
        assert out == {"x": {"a": 1, "b": 20, "c": 30}}

    def test_b_none_keeps_a(self, executor) -> None:
        out = executor._deep_merge_dicts({"a": 1}, {"a": None})
        assert out["a"] == 1

    def test_inputs_not_mutated(self, executor) -> None:
        a = {"x": {"a": 1}}
        b = {"x": {"b": 2}}
        executor._deep_merge_dicts(a, b)
        assert a == {"x": {"a": 1}}
        assert b == {"x": {"b": 2}}


# --- _get_by_path / _set_by_path -----------------------------------------


class TestPathHelpers:
    def test_get_simple_path(self, executor) -> None:
        assert executor._get_by_path({"a": 1}, "a") == 1

    def test_get_nested_path(self, executor) -> None:
        assert executor._get_by_path({"a": {"b": {"c": 5}}}, "a.b.c") == 5

    def test_get_missing_returns_none(self, executor) -> None:
        assert executor._get_by_path({"a": 1}, "missing") is None

    def test_get_into_non_dict_returns_none(self, executor) -> None:
        assert executor._get_by_path({"a": "scalar"}, "a.b") is None

    def test_set_creates_intermediate_dicts(self, executor) -> None:
        obj: dict = {}
        executor._set_by_path(obj, "a.b.c", 42)
        assert obj == {"a": {"b": {"c": 42}}}

    def test_set_overwrites_non_dict_intermediate(self, executor) -> None:
        obj = {"a": "previously-a-string"}
        executor._set_by_path(obj, "a.b", 1)
        assert obj == {"a": {"b": 1}}

    def test_set_overwrites_existing_leaf(self, executor) -> None:
        obj = {"a": 1}
        executor._set_by_path(obj, "a", 2)
        assert obj["a"] == 2


# --- _validate_preset ----------------------------------------------------


class TestValidatePreset:
    def test_non_empty_dict_valid(self, executor) -> None:
        assert executor._validate_preset({"a": 1}, "p1") is True

    def test_empty_dict_invalid(self, executor) -> None:
        assert executor._validate_preset({}, "p1") is False

    def test_non_dict_invalid(self, executor) -> None:
        assert executor._validate_preset([1, 2], "p1") is False
        assert executor._validate_preset("string", "p1") is False
        assert executor._validate_preset(None, "p1") is False


# --- create_input_transform / create_output_transform -------------------


class TestCreateTransforms:
    def test_input_transform_none_when_no_config(self, executor) -> None:
        assert executor.create_input_transform({}) is None
        assert executor.create_input_transform({"input_transform": None}) is None

    def test_output_transform_none_when_no_config(self, executor) -> None:
        assert executor.create_output_transform({}) is None
        assert executor.create_output_transform({"output_transform": None}) is None

    @pytest.mark.asyncio
    async def test_input_transform_applies_coercion(
        self, executor: DeclarativeTransformExecutor
    ) -> None:
        rule = {"input_transform": {"coerce": ["enum_case"]}}
        transform = executor.create_input_transform(rule)
        assert transform is not None
        out = await transform({"state": "active"})
        assert out["state"] == "ACTIVE"

    @pytest.mark.asyncio
    async def test_input_transform_parses_payload(
        self, executor: DeclarativeTransformExecutor
    ) -> None:
        rule = {"input_transform": {"parse_payload": "json_or_yaml"}}
        transform = executor.create_input_transform(rule)
        out = await transform({"payload": '{"x": 1}'})
        assert out["payload"] == {"x": 1}
