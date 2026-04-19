"""Locked error codes for the `report_fields` tool family.

These codes are the contract between the tool surface and any caller (agents,
tests, dashboards). See adsv1.md §4.3 for the canonical list.

Any change to this enum is a spec change — update adsv1.md first, then here.
"""

from enum import Enum


class ReportFieldsErrorCode(str, Enum):
    """Locked five-member error enumeration for the report_fields tool.

    Declaration order is meaningful — iteration order stays stable so logs and
    dashboards remain deterministic. Do not reorder.
    """

    INVALID_MODE_ARGS = "INVALID_MODE_ARGS"
    UNSUPPORTED_OPERATION = "UNSUPPORTED_OPERATION"
    CATALOG_SCHEMA_MISMATCH = "CATALOG_SCHEMA_MISMATCH"
    INVALID_INPUT_SIZE = "INVALID_INPUT_SIZE"
    UNKNOWN_FIELD = "UNKNOWN_FIELD"
