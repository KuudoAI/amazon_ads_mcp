"""Tests for ReportFieldsErrorCode enum.

Locked contract from adsv1.md §4.3 — five error codes, stable string values,
declaration-order iteration for stable logging.
"""

from enum import Enum

from amazon_ads_mcp.tools.report_fields_errors import ReportFieldsErrorCode


def test_is_str_enum():
    """Must be a string-valued Enum so codes can be logged/serialized directly."""
    assert issubclass(ReportFieldsErrorCode, str)
    assert issubclass(ReportFieldsErrorCode, Enum)


def test_exactly_five_members():
    """Locked enumeration — do not add codes without a spec change."""
    members = list(ReportFieldsErrorCode)
    assert len(members) == 5, f"expected 5 codes, got {len(members)}: {members}"


def test_member_names_match_spec():
    """Every code from adsv1.md §4.3 is present with the exact spelling."""
    expected = {
        "INVALID_MODE_ARGS",
        "UNSUPPORTED_OPERATION",
        "CATALOG_SCHEMA_MISMATCH",
        "INVALID_INPUT_SIZE",
        "UNKNOWN_FIELD",
    }
    actual = {m.name for m in ReportFieldsErrorCode}
    assert actual == expected


def test_string_values_equal_names():
    """Value strings must equal the code names — no drift between logs and code."""
    for member in ReportFieldsErrorCode:
        assert member.value == member.name


def test_declaration_order_stable():
    """Iteration order matches declaration order so logs/dashboards stay stable."""
    assert [m.name for m in ReportFieldsErrorCode] == [
        "INVALID_MODE_ARGS",
        "UNSUPPORTED_OPERATION",
        "CATALOG_SCHEMA_MISMATCH",
        "INVALID_INPUT_SIZE",
        "UNKNOWN_FIELD",
    ]


def test_str_equality_with_raw_string():
    """StrEnum behavior: members compare equal to their string value."""
    assert ReportFieldsErrorCode.INVALID_MODE_ARGS == "INVALID_MODE_ARGS"
    assert "CATALOG_SCHEMA_MISMATCH" == ReportFieldsErrorCode.CATALOG_SCHEMA_MISMATCH
