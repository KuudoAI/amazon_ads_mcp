"""Handler for the ``report_fields`` MCP tool.

See adsv1.md §4.3, §4.4, §4.5, §4.6, §4.10, §4.11 for the full locked
contract. This module owns:

- ``ReportFieldsInput`` — the schema-hardened input model (extra="forbid",
  limit ≤ 100 at Pydantic layer).
- ``ReportFieldsToolError`` — error with a locked ``ReportFieldsErrorCode``.
- ``handle(...)`` — the entry point. Dispatches on ``mode``.
- ``_serialize_with_byte_cap(...)`` — serializer-boundary byte cap with
  ``truncated_reason`` signal.

The handler reads catalog data via ``report_fields_v1_catalog`` (Phase C
loader). It never opens files directly.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Literal, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ..models.builtin_responses import (
    CatalogSourceMeta,
    QueryReportFieldsResponse,
    ReportFieldEntry,
    ValidateReportFieldsResponse,
)
from . import report_fields as baseline_mod
from . import report_fields_v1_catalog as catalog_mod
from .report_fields_errors import ReportFieldsErrorCode

logger = logging.getLogger(__name__)

#: Locked aliases that resolve to the sole v1-operation-with-catalog.
V1_CANONICAL = baseline_mod.ADSAPI_V1_CREATE  # "allv1_AdsApiv1CreateReport"

#: Locked input-size caps (§4.10).
_MAX_FIELDS = 200
_MAX_VALIDATE_FIELDS = 200
_MAX_COMPATIBLE_WITH = 50
_MAX_REQUIRES = 50
_MAX_SEARCH_LEN = 200

#: Byte-cap defaults (§4.6). Env overrides read at call time.
_DEFAULT_MAX_BYTES = 16_384
_DEFAULT_STALE_DAYS = 90


class ReportFieldsToolError(ValueError):
    """Locked-code error raised by the handler."""

    def __init__(self, code: ReportFieldsErrorCode, message: str) -> None:
        super().__init__(message)
        self.code = code

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"{self.code.value}: {super().__str__()}"


# ---------- input model -------------------------------------------------


class ReportFieldsInput(BaseModel):
    """Schema-hardened input for the ``report_fields`` tool.

    Rejects unknown args via ``extra="forbid"``. ``limit`` is capped at
    100 at the Pydantic layer (schema constraint), not as a sanitation
    error — see adsv1.md §D.1.
    """

    model_config = ConfigDict(extra="forbid")

    mode: Literal["query", "validate"]
    operation: str = V1_CANONICAL

    # --- query-mode args ---
    category: Optional[Literal["dimension", "metric", "filter", "time"]] = None
    search: Optional[str] = None
    compatible_with: Optional[List[str]] = None
    requires: Optional[List[str]] = None
    fields: Optional[List[str]] = None
    include_v3_mapping: bool = False
    limit: int = Field(default=25, ge=0, le=100)
    offset: int = Field(default=0, ge=0)

    # --- validate-mode args ---
    validate_fields: Optional[List[str]] = None


# ---------- dispatch + cross-mode validation ----------------------------


_QUERY_ONLY_ARGS = {
    "category",
    "search",
    "compatible_with",
    "requires",
    "fields",
    "include_v3_mapping",
}
_VALIDATE_ONLY_ARGS = {"validate_fields"}


def _any_query_arg_set(inp: ReportFieldsInput) -> bool:
    return any(
        getattr(inp, name) not in (None, False) for name in _QUERY_ONLY_ARGS
    )


def _any_validate_arg_set(inp: ReportFieldsInput) -> bool:
    return inp.validate_fields is not None


def _check_mode_args(inp: ReportFieldsInput) -> None:
    if inp.mode == "query":
        if _any_validate_arg_set(inp):
            raise ReportFieldsToolError(
                ReportFieldsErrorCode.INVALID_MODE_ARGS,
                "validate_fields is only valid in mode='validate'",
            )
        if not _any_query_arg_set(inp):
            raise ReportFieldsToolError(
                ReportFieldsErrorCode.INVALID_MODE_ARGS,
                "mode='query' requires at least one of: category, search, "
                "compatible_with, requires, fields",
            )
    else:  # mode == "validate"
        if _any_query_arg_set(inp):
            raise ReportFieldsToolError(
                ReportFieldsErrorCode.INVALID_MODE_ARGS,
                "query-mode args are not valid in mode='validate'",
            )
        if not _any_validate_arg_set(inp):
            raise ReportFieldsToolError(
                ReportFieldsErrorCode.INVALID_MODE_ARGS,
                "mode='validate' requires validate_fields",
            )


def _check_input_caps(inp: ReportFieldsInput) -> None:
    caps: List[Tuple[str, Any, int]] = [
        ("fields", inp.fields, _MAX_FIELDS),
        ("validate_fields", inp.validate_fields, _MAX_VALIDATE_FIELDS),
        ("compatible_with", inp.compatible_with, _MAX_COMPATIBLE_WITH),
        ("requires", inp.requires, _MAX_REQUIRES),
    ]
    for name, value, cap in caps:
        if value is not None and len(value) > cap:
            raise ReportFieldsToolError(
                ReportFieldsErrorCode.INVALID_INPUT_SIZE,
                f"{name} exceeds cap of {cap} items (got {len(value)})",
            )
    if inp.search is not None and len(inp.search) > _MAX_SEARCH_LEN:
        raise ReportFieldsToolError(
            ReportFieldsErrorCode.INVALID_INPUT_SIZE,
            f"search exceeds cap of {_MAX_SEARCH_LEN} chars (got {len(inp.search)})",
        )


def _resolve_v1(operation: str) -> Optional[str]:
    """Resolve *operation* to the canonical v1 key, or None if not v1."""
    resolved = baseline_mod.resolve_operation_key(operation)
    if resolved == V1_CANONICAL:
        return resolved
    return None


# ---------- handler dispatch --------------------------------------------


def handle(**kwargs: Any):
    """Entry point. Returns a Query- or ValidateReportFieldsResponse."""
    try:
        inp = ReportFieldsInput(**kwargs)
    except ValidationError:
        # Pydantic errors propagate as-is; FastMCP turns them into ToolError.
        logger.warning(
            "report_fields_error",
            extra={"event": "report_fields_error", "code": "PYDANTIC_VALIDATION"},
        )
        raise

    _check_mode_args(inp)
    _check_input_caps(inp)

    logger.info(
        "report_fields_call",
        extra={
            "event": "report_fields_call",
            "mode": inp.mode,
            "operation": inp.operation,
        },
    )

    if inp.mode == "query":
        return _handle_query(inp)
    return _handle_validate(inp)


# ---------- query-mode --------------------------------------------------


def _record_to_entry(
    record: Dict[str, Any],
    *,
    include_description: bool,
    include_v3: bool,
) -> ReportFieldEntry:
    category = record["category"]
    source = record.get("source") or {}

    entry = ReportFieldEntry(
        field_id=record["field_id"],
        display_name=record.get("display_name", ""),
        data_type=record.get("data_type", "UNKNOWN"),
        category=category,
        provenance=record.get("provenance", "documented"),
        short_description=record.get("short_description", ""),
        description=record.get("description") if include_description else None,
        required_fields=list(record.get("required_fields") or []),
        complementary_fields=list(record.get("complementary_fields") or []),
        compatible_dimensions=(
            list(record.get("compatible_dimensions") or [])
            if category == "dimension"
            else None
        ),
        incompatible_dimensions=(
            list(record.get("incompatible_dimensions") or [])
            if category == "dimension"
            else None
        ),
        v3_name_dsp=record.get("v3_name_dsp") if include_v3 else None,
        v3_name_sponsored_ads=record.get("v3_name_sponsored_ads") if include_v3 else None,
        source=(
            CatalogSourceMeta(
                md_file=source.get("md_file") or "",
                parsed_at=source.get("parsed_at") or "",
            )
            if include_description and source.get("parsed_at")
            else None
        ),
    )
    return entry


def _parsed_at() -> str:
    meta = catalog_mod.get_catalog_meta()
    return meta.get("parsed_at", "")


def _stale_warning_or_none() -> Optional[str]:
    days = int(os.environ.get("LIST_REPORT_FIELDS_STALE_DAYS", _DEFAULT_STALE_DAYS))
    parsed = _parsed_at()
    if not parsed:
        return None
    try:
        ts = datetime.fromisoformat(parsed.replace("Z", "+00:00"))
    except ValueError:
        return None
    age = datetime.now(timezone.utc) - ts
    if age > timedelta(days=days):
        return (
            f"catalog parsed_at is {age.days} days old (threshold: {days} days); "
            f"refresh recommended"
        )
    return None


def _select_query_records(inp: ReportFieldsInput) -> List[Dict[str, Any]]:
    """Apply category filter + compatibility graph filters.

    Does NOT apply pagination, search, fields-lookup, or v3 gating;
    those are layered on top.
    """
    # category=filter or time → empty; they carry no records in v1 catalog yet (§D.2).
    if inp.category in ("filter", "time"):
        return []

    if inp.category == "dimension":
        pool: List[Dict[str, Any]] = list(catalog_mod.get_dimensions())
    elif inp.category == "metric":
        pool = list(catalog_mod.get_metrics())
    else:
        pool = list(catalog_mod.get_dimensions()) + list(catalog_mod.get_metrics())

    if inp.compatible_with:
        target = set(inp.compatible_with)
        pool = [
            r
            for r in pool
            if r.get("category") == "dimension"
            and target.issubset(set(r.get("compatible_dimensions") or []))
        ]

    if inp.requires:
        required_set = set(inp.requires)
        pool = [
            r
            for r in pool
            if set(r.get("required_fields") or []).issubset(required_set)
            and r.get("required_fields")  # exclude records with empty required_fields
        ]

    return pool


def _handle_query(inp: ReportFieldsInput) -> QueryReportFieldsResponse:
    # fields=[...] detail lookup path
    if inp.fields:
        entries: List[ReportFieldEntry] = []
        for fid in inp.fields:
            record = catalog_mod.lookup_field(fid)
            if record is not None:
                entries.append(
                    _record_to_entry(
                        record,
                        include_description=True,
                        include_v3=inp.include_v3_mapping,
                    )
                )
        entries.sort(key=lambda e: e.field_id)
        response = QueryReportFieldsResponse(
            mode="query",
            success=True,
            operation=inp.operation,
            catalog_schema_version=catalog_mod.SUPPORTED_SCHEMA_VERSION,
            parsed_at=_parsed_at(),
            stale_warning=_stale_warning_or_none(),
            total_matching=len(entries),
            returned=len(entries),
            offset=0,
            limit=len(entries),
            fields=entries,
        )
        return _serialize_with_byte_cap(response)

    # Standard filter+paginate path
    pool = _select_query_records(inp)

    if inp.search:
        needle = inp.search.lower()
        pool = [
            r
            for r in pool
            if needle in r.get("field_id", "").lower()
            or needle in r.get("display_name", "").lower()
        ]

    total = len(pool)
    paged = sorted(pool, key=lambda r: r["field_id"])[inp.offset : inp.offset + inp.limit]

    entries = [
        _record_to_entry(r, include_description=False, include_v3=inp.include_v3_mapping)
        for r in paged
    ]

    response = QueryReportFieldsResponse(
        mode="query",
        success=True,
        operation=inp.operation,
        catalog_schema_version=catalog_mod.SUPPORTED_SCHEMA_VERSION,
        parsed_at=_parsed_at(),
        stale_warning=_stale_warning_or_none(),
        total_matching=total,
        returned=len(entries),
        offset=inp.offset,
        limit=inp.limit,
        fields=entries,
    )
    return _serialize_with_byte_cap(response)


# ---------- validate-mode ----------------------------------------------


def _handle_validate(inp: ReportFieldsInput) -> ValidateReportFieldsResponse:
    resolved = _resolve_v1(inp.operation)
    if resolved is None:
        raise ReportFieldsToolError(
            ReportFieldsErrorCode.UNSUPPORTED_OPERATION,
            "validate mode supports only allv1_AdsApiv1CreateReport (the sole "
            "operation with a compatibility graph). For other report APIs, use "
            "list_report_fields(operation=...) to inspect their enumerated schemas.",
        )

    fields_to_check: List[str] = inp.validate_fields or []
    index = catalog_mod.get_index().get("fields", {})

    unknown: List[str] = []
    known: List[str] = []
    for fid in fields_to_check:
        if fid in index:
            known.append(fid)
        else:
            unknown.append(fid)

    known_set = set(known)

    missing_required: Dict[str, List[str]] = {}
    for fid in known:
        record = catalog_mod.lookup_field(fid) or {}
        req = record.get("required_fields") or []
        missing = [r for r in req if r not in known_set]
        if missing:
            missing_required[fid] = missing

    incompatible_pairs: List[Tuple[str, str]] = []
    seen_pairs: set[Tuple[str, str]] = set()
    for fid in known:
        record = catalog_mod.lookup_field(fid) or {}
        for other in record.get("incompatible_dimensions") or []:
            if other in known_set:
                pair = tuple(sorted((fid, other)))
                if pair not in seen_pairs:
                    incompatible_pairs.append(pair)
                    seen_pairs.add(pair)

    suggested: Dict[str, List[str]] = {}
    if unknown:
        all_ids = list(index.keys())
        for bad in unknown:
            suggested[bad] = _suggest_replacements(bad, all_ids)

    valid = not unknown and not missing_required and not incompatible_pairs

    response = ValidateReportFieldsResponse(
        mode="validate",
        success=True,
        operation=resolved,
        valid=valid,
        unknown_fields=unknown,
        missing_required=missing_required,
        incompatible_pairs=incompatible_pairs,
        suggested_replacements=suggested,
    )
    return response


def _suggest_replacements(bad: str, all_ids: List[str], top_n: int = 3) -> List[str]:
    """Return up to ``top_n`` catalog ids whose prefix up to the first '.'
    matches the bad id's prefix.

    Intentionally simple — the goal is to flag likely typos (``metric.click``
    vs ``metric.clicks``) without pulling in a fuzzy-match library.
    """
    prefix = bad.split(".")[0] if "." in bad else bad
    prefix_lower = prefix.lower()
    needle = bad.lower()

    # First tier: same prefix + substring similarity.
    tier1 = [c for c in all_ids if c.split(".")[0].lower() == prefix_lower]
    tier1.sort(
        key=lambda c: (
            abs(len(c) - len(bad)),
            0 if needle in c.lower() else 1,
            c,
        )
    )
    return tier1[:top_n]


# ---------- byte-cap at serializer boundary -----------------------------


def _env_max_bytes() -> int:
    try:
        return int(os.environ.get("LIST_REPORT_FIELDS_MAX_BYTES", _DEFAULT_MAX_BYTES))
    except ValueError:
        return _DEFAULT_MAX_BYTES


def _serialize_bytes(response: BaseModel) -> int:
    payload = response.model_dump(exclude_none=True)
    return len(json.dumps(payload).encode("utf-8"))


def _serialize_with_byte_cap(response: QueryReportFieldsResponse) -> QueryReportFieldsResponse:
    """Enforce the hard byte cap on the serialized response.

    Clipping strategy: walk entries left-to-right and shorten
    ``short_description`` first, then drop ``description`` if present.
    Never drop fields (§4.6). When a clip happens, mark ``truncated=True``
    and populate ``truncated_reason="byte_cap"``.
    """
    cap = _env_max_bytes()
    if _serialize_bytes(response) <= cap:
        return response

    # Clip descriptions in-place (new entries, don't mutate model fields).
    new_entries: List[ReportFieldEntry] = []
    for entry in response.fields:
        clipped = entry.model_copy(
            update={
                "description": None,
                "short_description": entry.short_description[:60],
            }
        )
        new_entries.append(clipped)

    truncated = response.model_copy(
        update={
            "fields": new_entries,
            "truncated": True,
            "truncated_reason": "byte_cap",
        }
    )

    logger.info(
        "report_fields_truncation",
        extra={"event": "report_fields_truncation", "reason": "byte_cap"},
    )
    return truncated
