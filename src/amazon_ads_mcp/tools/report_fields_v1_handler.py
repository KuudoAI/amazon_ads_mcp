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
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Literal, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ..models.builtin_responses import (
    CatalogSourceMeta,
    LookupReportFieldEntry,
    LookupReportFieldsResponse,
    QueryReportFieldsResponse,
    ReportFieldEntry,
    ValidateBodyReportFieldsResponse,
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
#: Cap for ``drop`` — far larger than any sensible field-record key set.
_MAX_DROP = 20

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

    mode: Literal["query", "validate", "lookup", "validate_body"]
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

    # --- lookup-mode args (Round 13 B-5) ---
    # Look up exactly the requested field IDs and return them in request
    # order. Misses surface as records with ``error: "not_found"``,
    # never raise. Caller picks ONE of ``field_id`` (shortcut) or
    # ``field_ids`` (batch); both-set is INVALID_MODE_ARGS.
    field_id: Optional[str] = None
    field_ids: Optional[List[str]] = None

    # --- validate_body-mode args (Round 13 C-1) ---
    # Full request-body shape validation. ``body`` is the would-be
    # CreateReport request body; the handler validates against the
    # SAME runtime schema the live tool uses (single source of truth
    # — pinned by the SSoT identity test) and surfaces shape errors,
    # unknown-fields with v1↔v3 alias suggestions, AND a curated
    # ``deprecated_shape_hints`` array for legit-looking-but-wrong
    # top-level keys (``name``, ``configuration``, ``query``).
    body: Optional[Dict[str, Any]] = None

    # --- response-shaping args ---
    # ``drop`` names top-level keys to omit from every field record in the
    # response. Query-mode only: validate-mode responses carry no field
    # records, so ``drop`` there is a contract violation rather than a
    # silent no-op (§D.1 — surface caller mistakes, don't hide them).
    # Values are checked against the ReportFieldEntry allowlist so typos
    # like ``"compatable_dimensions"`` raise INVALID_MODE_ARGS instead of
    # silently keeping the bytes the caller meant to drop. Required keys
    # (e.g. ``field_id``) are still removable — the allowlist gates known
    # vs unknown, not required vs optional.
    drop: Optional[List[str]] = None


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
_LOOKUP_ONLY_ARGS = {"field_id", "field_ids"}
_VALIDATE_BODY_ONLY_ARGS = {"body"}

#: Allowlist of keys that may appear in ``drop``. Derived from the
#: response-record model so adding a field to ReportFieldEntry
#: automatically widens the allowlist; renames are caught by callers
#: hardcoding the old name (loud failure, not silent waste of bytes).
#:
#: Design choice — the allowlist gates *known* vs *unknown* record keys,
#: NOT *required* vs *optional*. That means callers can strip
#: ``field_id`` and other Pydantic-required keys, and the response will
#: come back with malformed records by Pydantic standards.
#:
#: This is intentional. The alternative — refusing to drop required
#: keys — would require:
#:   1. Coupling the drop validator to Pydantic ``is_required``, a
#:      separate concern with its own change-management story.
#:   2. Per-key opinion on which keys are "safe" to drop, baking server
#:      taste into a parameter that exists precisely to give callers
#:      mechanical control over their payload shape.
#:   3. Breaking the legitimate "I want display names only for an
#:      autocomplete UI" use case where ``drop=["field_id", ...]`` is
#:      exactly the right call.
#:
#: The contract: "if it's a record key, you may strip it; if you strip
#: a required key, you own the malformed-shape downside." If usage
#: telemetry shows callers regularly stripping required keys by
#: accident, the right response is to add a separate ``view`` parameter
#: (named tiers) on top of ``drop`` rather than narrow the allowlist.
_DROP_ALLOWED_KEYS: frozenset[str] = frozenset(ReportFieldEntry.model_fields.keys())


def _any_query_arg_set(inp: ReportFieldsInput) -> bool:
    return any(
        getattr(inp, name) not in (None, False) for name in _QUERY_ONLY_ARGS
    )


def _any_validate_arg_set(inp: ReportFieldsInput) -> bool:
    return inp.validate_fields is not None


def _any_lookup_arg_set(inp: ReportFieldsInput) -> bool:
    return inp.field_id is not None or inp.field_ids is not None


def _any_validate_body_arg_set(inp: ReportFieldsInput) -> bool:
    return inp.body is not None


def _check_mode_args(inp: ReportFieldsInput) -> None:
    if inp.mode == "query":
        if _any_validate_arg_set(inp):
            raise ReportFieldsToolError(
                ReportFieldsErrorCode.INVALID_MODE_ARGS,
                "validate_fields is only valid in mode='validate'",
            )
        if _any_lookup_arg_set(inp):
            raise ReportFieldsToolError(
                ReportFieldsErrorCode.INVALID_MODE_ARGS,
                "field_id / field_ids are only valid in mode='lookup'",
            )
        if _any_validate_body_arg_set(inp):
            raise ReportFieldsToolError(
                ReportFieldsErrorCode.INVALID_MODE_ARGS,
                "body is only valid in mode='validate_body'",
            )
        if not _any_query_arg_set(inp):
            raise ReportFieldsToolError(
                ReportFieldsErrorCode.INVALID_MODE_ARGS,
                "mode='query' requires at least one of: category, search, "
                "compatible_with, requires, fields",
            )
    elif inp.mode == "validate":
        if _any_query_arg_set(inp):
            raise ReportFieldsToolError(
                ReportFieldsErrorCode.INVALID_MODE_ARGS,
                "query-mode args are not valid in mode='validate'",
            )
        if _any_lookup_arg_set(inp):
            raise ReportFieldsToolError(
                ReportFieldsErrorCode.INVALID_MODE_ARGS,
                "field_id / field_ids are only valid in mode='lookup'",
            )
        if _any_validate_body_arg_set(inp):
            raise ReportFieldsToolError(
                ReportFieldsErrorCode.INVALID_MODE_ARGS,
                "body is only valid in mode='validate_body'",
            )
        if inp.drop:
            raise ReportFieldsToolError(
                ReportFieldsErrorCode.INVALID_MODE_ARGS,
                "drop is a query-mode-only response-shaping arg; "
                "mode='validate' returns no field records to shape",
            )
        if not _any_validate_arg_set(inp):
            raise ReportFieldsToolError(
                ReportFieldsErrorCode.INVALID_MODE_ARGS,
                "mode='validate' requires validate_fields",
            )
    elif inp.mode == "lookup":
        if _any_query_arg_set(inp):
            raise ReportFieldsToolError(
                ReportFieldsErrorCode.INVALID_MODE_ARGS,
                "query-mode args (search, category, limit, ...) are not "
                "valid in mode='lookup'",
            )
        if _any_validate_arg_set(inp):
            raise ReportFieldsToolError(
                ReportFieldsErrorCode.INVALID_MODE_ARGS,
                "validate_fields is only valid in mode='validate'",
            )
        if _any_validate_body_arg_set(inp):
            raise ReportFieldsToolError(
                ReportFieldsErrorCode.INVALID_MODE_ARGS,
                "body is only valid in mode='validate_body'",
            )
        if not _any_lookup_arg_set(inp):
            raise ReportFieldsToolError(
                ReportFieldsErrorCode.INVALID_MODE_ARGS,
                "mode='lookup' requires either field_id (single) or "
                "field_ids (batch)",
            )
        if inp.field_id is not None and inp.field_ids is not None:
            raise ReportFieldsToolError(
                ReportFieldsErrorCode.INVALID_MODE_ARGS,
                "mode='lookup' takes either field_id (single) or "
                "field_ids (batch), not both",
            )
    else:  # mode == "validate_body"
        if _any_query_arg_set(inp):
            raise ReportFieldsToolError(
                ReportFieldsErrorCode.INVALID_MODE_ARGS,
                "query-mode args are not valid in mode='validate_body'",
            )
        if _any_validate_arg_set(inp):
            raise ReportFieldsToolError(
                ReportFieldsErrorCode.INVALID_MODE_ARGS,
                "validate_fields is only valid in mode='validate'; use "
                "mode='validate_body' to shape-check the full request body",
            )
        if _any_lookup_arg_set(inp):
            raise ReportFieldsToolError(
                ReportFieldsErrorCode.INVALID_MODE_ARGS,
                "field_id / field_ids are only valid in mode='lookup'",
            )
        if not _any_validate_body_arg_set(inp):
            raise ReportFieldsToolError(
                ReportFieldsErrorCode.INVALID_MODE_ARGS,
                "mode='validate_body' requires body (the would-be "
                "CreateReport request body dict)",
            )

    if inp.drop:
        unknown = sorted(set(inp.drop) - _DROP_ALLOWED_KEYS)
        if unknown:
            allowed = ", ".join(sorted(_DROP_ALLOWED_KEYS))
            raise ReportFieldsToolError(
                ReportFieldsErrorCode.INVALID_MODE_ARGS,
                f"drop contains unknown record key(s): {unknown}. "
                f"Allowed: [{allowed}]",
            )


def _check_input_caps(inp: ReportFieldsInput) -> None:
    caps: List[Tuple[str, Any, int]] = [
        ("fields", inp.fields, _MAX_FIELDS),
        ("validate_fields", inp.validate_fields, _MAX_VALIDATE_FIELDS),
        ("compatible_with", inp.compatible_with, _MAX_COMPATIBLE_WITH),
        ("requires", inp.requires, _MAX_REQUIRES),
        ("drop", inp.drop, _MAX_DROP),
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

    # Structural caps run first (cheap, mechanical) so size violations
    # always surface as INVALID_INPUT_SIZE regardless of the contents
    # being otherwise well-formed. Semantic mode-arg checks run second.
    _check_input_caps(inp)
    _check_mode_args(inp)

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
    if inp.mode == "lookup":
        return _handle_lookup(inp)
    if inp.mode == "validate_body":
        return _handle_validate_body(inp)
    return _handle_validate(inp)


# ---------- query-mode --------------------------------------------------


def _record_to_entry(
    record: Dict[str, Any],
    *,
    include_description: bool,
    include_v3: bool,
) -> ReportFieldEntry:
    """Project a catalog record onto a ReportFieldEntry.

    compat lists are emitted from whichever side of the graph has data:
      - metric records carry source-side ``compatible_dimensions`` /
        ``incompatible_dimensions`` (Amazon populates these per-metric).
      - dimension records carry the refresh-time inverted index
        (``compatible_metrics`` / ``incompatible_metrics``) so the graph
        is queryable from either direction.
    None is emitted (→ dropped by exclude_none) only when the record
    has nothing useful to report.
    """
    category = record["category"]
    source = record.get("source") or {}

    def _nonempty_or_none(key: str) -> Optional[List[str]]:
        vals = record.get(key)
        if not vals:
            return None
        return list(vals)

    def _resolve_labels_to_ids(labels_key: str) -> Optional[List[str]]:
        """Round 13 Phase D — resolve display-label compatibility
        lists to canonical field_ids via the catalog's
        dimension_label_index. Empty/missing input → None (drops
        cleanly via exclude_none)."""
        labels = record.get(labels_key) or []
        if not labels:
            return None
        try:
            label_index = catalog_mod.get_dimension_label_index() or {}
        except Exception:
            return None
        out: List[str] = []
        seen: set[str] = set()
        for label in labels:
            for fid in label_index.get(label, []) or []:
                if fid not in seen:
                    out.append(fid)
                    seen.add(fid)
        return out or None

    entry_kwargs: Dict[str, Any] = dict(
        field_id=record["field_id"],
        display_name=record.get("display_name", ""),
        data_type=record.get("data_type", "UNKNOWN"),
        category=category,
        provenance=record.get("provenance", "documented"),
        short_description=record.get("short_description", ""),
        description=record.get("description") if include_description else None,
        required_fields=list(record.get("required_fields") or []),
        complementary_fields=list(record.get("complementary_fields") or []),
        compatible_dimensions=_nonempty_or_none("compatible_dimensions"),
        incompatible_dimensions=_nonempty_or_none("incompatible_dimensions"),
        # Round 13 Phase D: parallel field-id arrays. Display strings
        # remain through 2026-09-30 (see top-level ``deprecations[]``).
        compatible_dimension_ids=_resolve_labels_to_ids("compatible_dimensions"),
        incompatible_dimension_ids=_resolve_labels_to_ids("incompatible_dimensions"),
        source=(
            CatalogSourceMeta(
                md_file=source.get("md_file") or "",
                parsed_at=source.get("parsed_at") or "",
            )
            if include_description and source.get("parsed_at")
            else None
        ),
    )
    if include_v3:
        entry_kwargs["v3_name_dsp"] = record.get("v3_name_dsp")
        entry_kwargs["v3_name_sponsored_ads"] = record.get("v3_name_sponsored_ads")
    # Dimension inverted-index lists can be up to ~700 items on hub
    # dimensions (e.g. campaign.id) — emitting them in a listing response
    # would blow the 16 KB byte cap in a single record. Restrict them to
    # detail-lookup mode (fields=[...], same gate as description+source).
    if include_description:
        entry_kwargs["compatible_metrics"] = _nonempty_or_none("compatible_metrics")
        entry_kwargs["incompatible_metrics"] = _nonempty_or_none("incompatible_metrics")
    return ReportFieldEntry(**entry_kwargs)


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


def _resolve_to_field_ids(values: List[str]) -> set[str]:
    """Translate a list of ``compatible_with``/``requires`` inputs to field IDs.

    Each input may be either:
    - a canonical field_id already present in the catalog index, or
    - an Amazon display label (e.g. ``"Ad group"``) resolvable via the
      dimension_label_index.

    Unknown inputs (neither field_id nor label) resolve to nothing; the
    caller sees an empty result set rather than an error.
    """
    index = (catalog_mod.get_index() or {}).get("fields", {})
    label_index = catalog_mod.get_dimension_label_index() or {}
    out: set[str] = set()
    for value in values:
        if value in index:
            out.add(value)
            continue
        for fid in label_index.get(value, []):
            out.add(fid)
    return out


def _compat_labels_for_metric(record: Dict[str, Any]) -> set[str]:
    """Translate a metric record's stored display labels to field IDs."""
    label_index = catalog_mod.get_dimension_label_index() or {}
    out: set[str] = set()
    for label in record.get("compatible_dimensions") or []:
        for fid in label_index.get(label, []):
            out.add(fid)
    return out


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
        # Source-side relation: metric.compatible_dimensions lists display
        # labels of dimensions the metric is compatible with. Resolve the
        # caller's inputs (either field_ids or labels) to the canonical
        # dim field_ids the metric references.
        target_fids = _resolve_to_field_ids(inp.compatible_with)

        if not target_fids:
            # Caller passed values that resolved to nothing — unknown label
            # or id. Don't let empty-set-is-subset-of-anything match every
            # record; return an empty pool. (The spec's "unknown inputs
            # return empty results, not errors" policy.)
            pool = []
        else:
            # compatible_with is semantically "give me the things I can
            # pair alongside these field ids". For metrics that means
            # target_fids must all appear in the metric's compatible
            # dimension set (via label resolution). Dims don't carry
            # source-side compat lists, so the filter only applies to
            # metrics here — users query from the metric side.
            pool = [
                r
                for r in pool
                if r.get("category") == "metric"
                and target_fids.issubset(_compat_labels_for_metric(r))
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
    drop_set: Optional[set[str]] = set(inp.drop) if inp.drop else None

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
            deprecations=list(_QUERY_DEPRECATIONS),
        )
        return _serialize_with_byte_cap(response, drop=drop_set)

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
        deprecations=list(_QUERY_DEPRECATIONS),
        total_matching=total,
        returned=len(entries),
        offset=inp.offset,
        limit=inp.limit,
        fields=entries,
    )
    return _serialize_with_byte_cap(response, drop=drop_set)


# ---------- lookup-mode (Round 13 B-5) ---------------------------------


def _record_to_lookup_entry(
    record: Dict[str, Any],
    *,
    include_v3: bool,
    drop_set: Optional[set[str]] = None,
) -> LookupReportFieldEntry:
    """Project a catalog record onto a LookupReportFieldEntry.

    Mirrors ``_record_to_entry`` but emits the lookup-mode model. Always
    includes the description (lookup is a detail-level access path).
    """
    base = _record_to_entry(record, include_description=True, include_v3=include_v3)
    payload = base.model_dump(exclude_none=True)
    if drop_set:
        payload = {k: v for k, v in payload.items() if k not in drop_set}
    return LookupReportFieldEntry(**payload)


def _handle_lookup(inp: ReportFieldsInput) -> LookupReportFieldsResponse:
    """Strict ID lookup. Returns one record per requested field_id in
    request order; misses surface as ``error="not_found"`` records."""
    resolved = _resolve_v1(inp.operation)
    if resolved is None:
        raise ReportFieldsToolError(
            ReportFieldsErrorCode.UNSUPPORTED_OPERATION,
            "lookup mode supports only allv1_AdsApiv1CreateReport. For "
            "other report APIs, use list_report_fields(operation=...).",
        )

    requested_ids: List[str] = (
        [inp.field_id] if inp.field_id is not None else list(inp.field_ids or [])
    )

    drop_set: Optional[set[str]] = set(inp.drop) if inp.drop else None

    out: List[LookupReportFieldEntry] = []
    found = 0
    missing = 0
    for fid in requested_ids:
        record = catalog_mod.lookup_field(fid)
        if record is None:
            out.append(LookupReportFieldEntry(field_id=fid, error="not_found"))
            missing += 1
        else:
            out.append(
                _record_to_lookup_entry(
                    record, include_v3=inp.include_v3_mapping, drop_set=drop_set
                )
            )
            found += 1

    return LookupReportFieldsResponse(
        mode="lookup",
        success=True,
        operation=resolved,
        catalog_schema_version=catalog_mod.SUPPORTED_SCHEMA_VERSION,
        parsed_at=_parsed_at(),
        stale_warning=_stale_warning_or_none(),
        requested=len(requested_ids),
        found=found,
        missing=missing,
        fields=out,
    )


# ---------- validate_body-mode (Round 13 Phase C-1 + C-2) ------------


#: Round 13 Phase C-2 — filter operator misuse table. The v1
#: ``ComparisonOperator`` enum allows ONLY ``EQUALS`` and ``IN``
#: (per the live AdsApiv1All spec). SQL/v3 reflexes (BETWEEN, LIKE,
#: NOT_IN) are caught here with curated replacement guidance pointing
#: at the v1-correct path.
#:
#: BETWEEN specifically redirects date ranges to ``periods[].datePeriod``
#: — that's the actual v1 mechanism for date filtering, NOT a filter
#: with BETWEEN-shaped values. The client report flagged this as the
#: highest-leverage natural-language reflex.
OPERATOR_MISUSE: Dict[str, Tuple[str, List[str]]] = {
    "BETWEEN": (
        "BETWEEN is not supported on filters. Date ranges go in "
        "`periods[].datePeriod` (with `startDate` / `endDate`), NOT "
        "in a filter with BETWEEN-shaped values. For non-date ranges, "
        "use EQUALS or IN with explicit values.",
        ["EQUALS", "IN"],
    ),
    "LIKE": (
        "LIKE is not supported on v1 filters. Use EQUALS for exact "
        "match or IN with the explicit list of values you want.",
        ["EQUALS", "IN"],
    ),
    "NOT_IN": (
        "NOT_IN is not supported on v1 filters. Either invert the "
        "filter logic (filter for values you DO want), or use the "
        "report's exclusion mechanism if available for your dimension.",
        ["IN"],
    ),
}


def _walk_filters_for_misuse(container: Any, path: str = "") -> List[Dict[str, Any]]:
    """Recursively walk the body for filter dicts with bad operators.

    Filter shapes vary across v1 endpoints (singular ``filter``,
    plural ``filters[]``, nested under ``query``, etc.). This walker
    handles all common shapes: any dict carrying an ``operator`` key
    is checked; nested dicts/lists are recursed.
    """
    out: List[Dict[str, Any]] = []
    if isinstance(container, dict):
        op = container.get("operator")
        if isinstance(op, str) and op in OPERATOR_MISUSE:
            message, replacements = OPERATOR_MISUSE[op]
            out.append(
                {
                    "kind": "operator_misuse",
                    "operator": op,
                    "path": path or "filter",
                    "message": message,
                    "replacement": list(replacements),
                }
            )
        for k, v in container.items():
            out.extend(
                _walk_filters_for_misuse(
                    v, path=f"{path}.{k}" if path else k
                )
            )
    elif isinstance(container, list):
        for i, item in enumerate(container):
            out.extend(
                _walk_filters_for_misuse(
                    item, path=f"{path}[{i}]" if path else f"[{i}]"
                )
            )
    return out


#: Top-level keys the live AdsApiv1CreateReport schema accepts. Mirrors
#: the runtime schema's ``properties`` keys at the top level. When the
#: runtime schema gains/loses a top-level key, update here and the
#: drift test in ``tests/unit/test_validate_body_and_deprecated_shapes.py``
#: catches the change. Single-source-of-truth follow-up: pull this from
#: the live tool's `parameters.properties.keys()` at registration time
#: so it's structurally guaranteed to match. Tracked as a Round 14
#: hardening item.
_CREATE_REPORT_TOP_LEVEL_KEYS: frozenset[str] = frozenset(
    {"accessRequestedAccounts", "reports"}
)
_CREATE_REPORT_REQUIRED_KEYS: frozenset[str] = frozenset(
    {"accessRequestedAccounts"}
)


def _handle_validate_body(
    inp: ReportFieldsInput,
) -> ValidateBodyReportFieldsResponse:
    """Round 13 Phase C-1 — full request-body shape validation.

    Surfaces shape errors AND ``deprecated_shape_hints`` for the
    legit-looking-but-wrong top-level keys (``name``, ``configuration``,
    ``query``) the client report flagged. Doesn't replace mode='validate'
    — runs alongside it; agents call validate_body for whole-request
    correctness and validate for cherry-picked field-list correctness.
    """
    resolved = _resolve_v1(inp.operation)
    if resolved is None:
        raise ReportFieldsToolError(
            ReportFieldsErrorCode.UNSUPPORTED_OPERATION,
            "validate_body mode supports only "
            "allv1_AdsApiv1CreateReport.",
        )

    body = inp.body or {}
    shape_errors: List[Dict[str, Any]] = []
    unknown_fields: List[str] = []
    deprecated_hints: List[str] = []
    suggested: Dict[str, List[str]] = {}
    operator_misuse: List[Dict[str, Any]] = []

    if not isinstance(body, dict):
        shape_errors.append(
            {
                "code": "SCHEMA_TYPE_MISMATCH",
                "field": "",
                "issue": "body must be an object",
            }
        )
    else:
        for key in body.keys():
            if key in _CREATE_REPORT_TOP_LEVEL_KEYS:
                continue
            unknown_fields.append(key)
            # Curated deprecated-shape table first — semantic intent.
            if key in DEPRECATED_V1_SHAPE_KEYS:
                deprecated_hints.append(DEPRECATED_V1_SHAPE_KEYS[key])
            # Catalog-aware suggestions for any unknown key.
            sugg = catalog_suggestions_for(key, body=body)
            if sugg:
                suggested[key] = sugg

        for required in _CREATE_REPORT_REQUIRED_KEYS:
            if required not in body:
                shape_errors.append(
                    {
                        "code": "SCHEMA_REQUIRED",
                        "field": required,
                        "issue": (
                            f"Required field missing: '{required}'."
                        ),
                    }
                )

        # Round 13 Phase C-2: filter operator-misuse detection.
        operator_misuse = _walk_filters_for_misuse(body)

    missing_required = sorted(
        e["field"]
        for e in shape_errors
        if e.get("code") == "SCHEMA_REQUIRED" and e.get("field")
    )

    valid = (
        not shape_errors
        and not unknown_fields
        and not deprecated_hints
        and not operator_misuse
    )

    return ValidateBodyReportFieldsResponse(
        mode="validate_body",
        success=True,
        operation=resolved,
        valid=valid,
        shape_errors=shape_errors,
        unknown_fields=unknown_fields,
        missing_required=missing_required,
        deprecated_shape_hints=deprecated_hints,
        suggested_replacements=suggested,
        operator_misuse=operator_misuse,
    )


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
    label_index = catalog_mod.get_dimension_label_index() or {}
    for fid in known:
        record = catalog_mod.lookup_field(fid) or {}
        # Source-side incompatibility (metric records): labels → field_ids.
        for label in record.get("incompatible_dimensions") or []:
            for other_fid in label_index.get(label, []):
                if other_fid in known_set and other_fid != fid:
                    pair = tuple(sorted((fid, other_fid)))
                    if pair not in seen_pairs:
                        incompatible_pairs.append(pair)
                        seen_pairs.add(pair)
        # Inverted side (dimension records): direct field_ids.
        for other_fid in record.get("incompatible_metrics") or []:
            if other_fid in known_set and other_fid != fid:
                pair = tuple(sorted((fid, other_fid)))
                if pair not in seen_pairs:
                    incompatible_pairs.append(pair)
                    seen_pairs.add(pair)

    suggested: Dict[str, List[str]] = {}
    if unknown:
        # Round 13 follow-up (post-Phase C client retest): pre-flight
        # mode='validate' previously used the token-only
        # ``_suggest_replacements`` and so missed v1↔v3 semantic
        # migrations like ``keyword.text → target.value`` and
        # ``metric.spend → metric.totalCost`` (cross-prefix +
        # override-mode noise suppression). Route through
        # ``catalog_suggestions_for`` instead so pre-flight surfaces
        # the SAME curated table the post-failure envelope uses —
        # agents get consistent guidance whether they call validate
        # before or learn from the 4xx after.
        for bad in unknown:
            sugg = catalog_suggestions_for(bad)
            if not sugg:
                # Fall back to the legacy token-overlap suggester
                # only when the curated path returns nothing — keeps
                # behavior monotonic vs the pre-Round-13 baseline.
                all_ids = list(index.keys())
                sugg = _suggest_replacements(bad, all_ids)
            if sugg:
                suggested[bad] = sugg

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


#: camelCase-aware tokenizer. Splits "metric.totalCost" → ["metric","total","cost"]
#: and "metric.DSPAdId" → ["metric","dsp","ad","id"]. Lowercases in _tokens.
_TOKEN_RE = re.compile(r"[A-Z]?[a-z0-9]+|[A-Z]+(?=[A-Z]|$)")


def _tokens(field_id: str) -> set[str]:
    """Tokenize the suffix (after the first dot) into a lowercase set.

    Used for token-overlap scoring in _suggest_replacements. We ignore
    the prefix because the prefix is already an exact-match gate.
    """
    suffix = field_id.split(".", 1)[-1]
    return {t.lower() for t in _TOKEN_RE.findall(suffix) if t}


def _suggest_replacements(bad: str, all_ids: List[str], top_n: int = 3) -> List[str]:
    """Rank candidates by camelCase token overlap + substring containment.

    Same-prefix candidates get priority (`metric.*` stays within `metric.*`).
    Scoring (lower wins):
        (-jaccard - 0.5*substring_bonus, abs(len_diff), alphabetical)

    Deterministic, no external dependencies. Catches typos like
    ``metric.cost`` → ``metric.totalCost`` which the old prefix-only
    suggester missed because ``"metric.cost" in "metric.totalCost"`` is
    False (the dot before ``cost`` doesn't appear in the target).
    """
    prefix = bad.split(".", 1)[0].lower() if "." in bad else bad.lower()
    bad_tokens = _tokens(bad)
    bad_suffix = bad.split(".", 1)[-1].lower()

    candidates = [c for c in all_ids if c.split(".", 1)[0].lower() == prefix and c != bad]

    def score(c: str) -> Tuple[float, int, str]:
        c_tokens = _tokens(c)
        c_suffix = c.split(".", 1)[-1].lower()
        denom = max(1, len(bad_tokens | c_tokens))
        jaccard = len(bad_tokens & c_tokens) / denom
        # Substring bonus in either direction — catches "cost" ⊂ "totalcost".
        substr = 1 if (bad_suffix in c_suffix or c_suffix in bad_suffix) else 0
        # Edge bonus — one suffix is a prefix OR trailing suffix of the other.
        # Catches pluralization (click → clicks) and compound extensions
        # (cost → totalCost) that generic substring matching under-weights
        # when longer records also share the substring.
        edge = 1 if (
            c_suffix.startswith(bad_suffix)
            or c_suffix.endswith(bad_suffix)
            or bad_suffix.startswith(c_suffix)
            or bad_suffix.endswith(c_suffix)
        ) else 0
        # Lower score wins.
        return (-jaccard - 0.5 * substr - 1.0 * edge, abs(len(c) - len(bad)), c)

    return sorted(candidates, key=score)[:top_n]


# ---------- catalog-aware did-you-mean (Round 13 C-pre) ----------------


#: Curated v1↔v3 / Sponsored-Ads-v2 alias table (Round 13 Phase C-4).
#:
#: Keyed by the bad field name an agent typically types. Each entry is
#: a 4-tuple ``(canonical, note, applies_when, mode)``:
#:
#:   - ``canonical``: the v1 field_id the agent should use instead.
#:   - ``note``: human-readable rationale; MUST carry caveats where
#:     the mapping is approximate (e.g. ``keyword.id`` has no stable
#:     v1 equivalent — the note explains the dedup/uniqueness gap).
#:   - ``applies_when``: optional dict keyed against the request body
#:     (e.g. ``{"adProduct": "SPONSORED_PRODUCTS"}``) for context-
#:     specific aliases. ``None`` = always applies.
#:   - ``mode``: ``"override"`` suppresses token-overlap fallback (use
#:     when substring matches are pure noise — DSP pacing metrics for
#:     ``metric.spend``); ``"merge"`` keeps token-overlap suggestions
#:     after the curated one (use when same-family fallback is OK).
#:
#: Consulted by :func:`catalog_suggestions_for` BEFORE the existing
#: token-overlap algorithm so semantic intent wins over substring
#: coincidence (e.g. ``cost`` ⊂ ``totalCost``).
V1_ALIAS_MAP: Dict[str, Tuple[str, str, Optional[Dict[str, Any]], str]] = {
    "keyword.text": (
        "target.value",
        "v1 unifies keyword/target under target.*; use target.value "
        "for the keyword text/expression.",
        {"adProduct": "SPONSORED_PRODUCTS"},
        "merge",
    ),
    "keyword.matchType": (
        "target.matchType",
        "v1 unifies keyword/target under target.*",
        None,
        "merge",
    ),
    "keyword.id": (
        "target.value",
        "v1 has NO STABLE ID EQUIVALENT for v3 keyword.id. "
        "target.value is the keyword text/expression that matched — "
        "NOT an ID. Caveat: the same keyword text under multiple ad "
        "groups appears as multiple target.value rows; v1 does NOT "
        "deduplicate by keyword identity the way v3 keyword.id did. "
        "If you need row-level uniqueness or stable join keys, no v1 "
        "mapping exists — restructure the query.",
        None,
        "merge",
    ),
    "metric.cost": (
        "metric.totalCost",
        "v1 renames cost → totalCost. Substring-matched DSP cost "
        "metrics (rewardCost, supplyCost) are kept as same-family "
        "fallbacks.",
        None,
        "merge",
    ),
    "metric.spend": (
        "metric.totalCost",
        "v1 renames spend → totalCost (Sponsored Ads vocabulary). "
        "Substring matches like currentFlightProjectedSpend are DSP "
        "pacing metrics — different semantic family; suppressed here.",
        None,
        "override",
    ),
    "metric.cpc": (
        "metric.costPerClick",
        "v1 spells out costPerClick instead of cpc.",
        None,
        "merge",
    ),
}


#: Round 13 Phase D — deprecation signal emitted on every query-mode
#: response. The display-string compatibility arrays
#: (``compatible_dimensions`` / ``incompatible_dimensions``) carry
#: presentation labels rather than canonical field_ids. Parallel
#: ``*_ids`` arrays ship in the same response; the legacy display
#: arrays will be removed no earlier than ``remove_after`` once two
#: consecutive client-conformance reports show zero usage AND no open
#: issues reference them.
_QUERY_DEPRECATIONS: List[Dict[str, Any]] = [
    {
        "kind": "field_renamed",
        "old": "compatible_dimensions",
        "new": "compatible_dimension_ids",
        "remove_after": "2026-09-30",
        "note": (
            "Display-string array carries human-facing labels (e.g. "
            "'Ad group') instead of canonical field_ids (e.g. "
            "'campaign.id'). Migrate to compatible_dimension_ids; both "
            "arrays ship today for the migration window."
        ),
    },
    {
        "kind": "field_renamed",
        "old": "incompatible_dimensions",
        "new": "incompatible_dimension_ids",
        "remove_after": "2026-09-30",
        "note": (
            "Same migration as compatible_dimensions. "
            "incompatible_dimension_ids ships today; the display-string "
            "form will be removed no earlier than 2026-09-30."
        ),
    },
]


#: Curated table of top-level keys that look plausible because they
#: appear in earlier API generations / v3 reporting tutorials but are
#: deprecated under v1's flat ``reports[*]`` layout. Round 13 Phase
#: C-1: keyed by the bad top-level key; value is the actionable
#: rewrite hint with v3-tutorial attribution. Used by
#: ``mode="validate_body"`` AND the runtime
#: ``SchemaValidationMiddleware`` SCHEMA_ADDITIONAL_PROPERTIES hint
#: enricher so live calls also get the curated guidance.
DEPRECATED_V1_SHAPE_KEYS: Dict[str, str] = {
    "name": (
        "Top-level `name` is an AdsApi v3 reporting shape. v1 has no "
        "`name` field on the report — earlier v3 docs took it at the "
        "request root, but the current v1 schema nests the report "
        "under `reports[*]` with `format`, `periods`, and `query` "
        "only. (You're likely working from a v3 tutorial.)"
    ),
    "configuration": (
        "Top-level `configuration` is an AdsApi v3 reporting shape. "
        "v1 flattens its fields onto each `reports[*]` element: "
        "`format`, `periods[*].datePeriod`, etc. — there is no "
        "`configuration` wrapper. (You're likely working from a v3 "
        "tutorial.)"
    ),
    "query": (
        "Top-level `query` is an AdsApi v3 reporting shape. v1 nests "
        "`query` under `reports[*].query` — each report carries its "
        "own query block; there is no top-level `query`. (You're "
        "likely working from a v3 tutorial.)"
    ),
}


def _alias_applies(applies_when: Optional[Dict[str, Any]], body: Optional[Dict[str, Any]]) -> bool:
    """Decide whether an ``applies_when`` filter accepts the request
    body. Lenient default: missing body context → assume the entry
    applies (a rare false positive beats an always-false negative when
    the caller can't supply context)."""
    if not applies_when:
        return True
    if not isinstance(body, dict):
        return True
    for key, expected in applies_when.items():
        actual = body.get(key)
        if actual != expected:
            return False
    return True


def catalog_suggestions_for(
    bad_field: str,
    top_n: int = 3,
    *,
    body: Optional[Dict[str, Any]] = None,
) -> List[str]:
    """Return up to *top_n* v1 catalog field_id suggestions for an
    unknown field name. Closes leverage gaps 2/3/4: schema-normalization
    and schema-validation paths reject unknown fields without consulting
    the catalog; this helper gives every consumer a single high-quality
    suggestion source.

    Resolution order:

      0. **Curated v1↔v3 alias table** (Round 13 C-4). Semantic
         migrations like ``keyword.text → target.value`` and
         ``metric.spend → metric.totalCost`` that token-overlap
         can't reach (no string similarity) or fights against (DSP
         pacing noise). Override mode suppresses token fallback;
         merge mode keeps it as same-family backup.
      1. **Exact display-label match** (e.g. caller passed ``"Campaign"``
         where ``campaign.id`` was expected) — catalog's
         ``dimension_label_index`` maps display labels to field_ids.
      2. **Case-insensitive label match** — same as (1) tolerating case.
      3. **Token-overlap fallback** — same algorithm
         ``_suggest_replacements`` uses inside validate-mode, but widened
         to ALL catalog field_ids regardless of prefix.

    ``body`` is the optional request body context for ``applies_when``
    filtering on curated entries (e.g. ``keyword.text`` only suggests
    ``target.value`` when ``adProduct=SPONSORED_PRODUCTS``).

    Empty list when no plausible match. Never raises.
    """
    if not isinstance(bad_field, str) or not bad_field:
        return []
    try:
        label_index = catalog_mod.get_dimension_label_index() or {}
        index = catalog_mod.get_index().get("fields", {})
    except Exception:
        return []

    out: List[str] = []
    seen: set[str] = set()
    suppress_token_fallback = False

    # (0) Curated v1↔v3 alias table — first because semantic intent
    # beats string similarity for cross-prefix migrations.
    alias_entry = V1_ALIAS_MAP.get(bad_field)
    if alias_entry is not None:
        canonical, _note, applies_when, mode = alias_entry
        if _alias_applies(applies_when, body):
            if canonical not in seen:
                out.append(canonical)
                seen.add(canonical)
            if mode == "override":
                # Substring matches are noise for this bad field
                # (e.g. metric.spend → DSP pacing metrics).
                suppress_token_fallback = True

    # (1) Exact label match.
    for fid in label_index.get(bad_field, []) or []:
        if fid not in seen:
            out.append(fid)
            seen.add(fid)

    # (2) Case-insensitive label match.
    if len(out) == (1 if alias_entry else 0):
        bad_lower = bad_field.lower()
        for label, fids in label_index.items():
            if label.lower() == bad_lower:
                for fid in fids or []:
                    if fid not in seen:
                        out.append(fid)
                        seen.add(fid)
                break

    # (3) Token-overlap fallback against the full field_id set.
    if not suppress_token_fallback and len(out) < top_n:
        all_ids = list(index.keys())
        token_suggestions = _suggest_replacements(
            bad_field, all_ids, top_n=top_n
        )
        # Widen beyond same-prefix when the algorithm returns nothing —
        # cross-prefix migrations (keyword.* → target.*) need this.
        if not token_suggestions:
            bad_tokens = _tokens(bad_field)
            scored: List[Tuple[float, str]] = []
            for cand in all_ids:
                cand_tokens = _tokens(cand)
                denom = max(1, len(bad_tokens | cand_tokens))
                jaccard = len(bad_tokens & cand_tokens) / denom
                if jaccard > 0:
                    scored.append((-jaccard, cand))
            scored.sort()
            token_suggestions = [cand for _, cand in scored[:top_n]]
        for cand in token_suggestions:
            if cand not in seen and len(out) < top_n:
                out.append(cand)
                seen.add(cand)

    return out[:top_n]


# ---------- byte-cap at serializer boundary -----------------------------


def _env_max_bytes() -> int:
    try:
        return int(os.environ.get("LIST_REPORT_FIELDS_MAX_BYTES", _DEFAULT_MAX_BYTES))
    except ValueError:
        return _DEFAULT_MAX_BYTES


def _apply_drop_to_payload(payload: Dict[str, Any], drop: Optional[set[str]]) -> Dict[str, Any]:
    """Strip caller-named top-level keys from each field record in *payload*.

    Mutates and returns *payload*. No-op when *drop* is empty or when the
    payload has no ``fields`` array (validate-mode response).
    """
    if not drop:
        return payload
    fields = payload.get("fields")
    if not isinstance(fields, list):
        return payload
    for entry in fields:
        for key in drop:
            entry.pop(key, None)
    return payload


def _serialize_bytes(
    response: BaseModel, drop: Optional[set[str]] = None
) -> int:
    payload = response.model_dump(exclude_none=True)
    _apply_drop_to_payload(payload, drop)
    return len(json.dumps(payload).encode("utf-8"))


def _serialize_with_byte_cap(
    response: QueryReportFieldsResponse,
    *,
    drop: Optional[set[str]] = None,
) -> QueryReportFieldsResponse:
    """Enforce the hard byte cap on the serialized response.

    Clipping strategy: walk entries left-to-right and shorten
    ``short_description`` first, then drop ``description`` if present.
    Never drop fields (§4.6). When a clip happens, mark ``truncated=True``
    and populate ``truncated_reason="byte_cap"``.

    The *drop* set (caller-supplied via ``ReportFieldsInput.drop``) is
    factored into the byte calculation so that callers who opted to
    strip large compatibility arrays don't pay clipping costs they
    avoided. The wire-level removal happens at the tool wrapper after
    ``model_dump``; the model itself is unchanged.
    """
    cap = _env_max_bytes()
    if _serialize_bytes(response, drop=drop) <= cap:
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
