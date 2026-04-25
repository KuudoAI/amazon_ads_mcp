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


def _rank_search_hit(record: Dict[str, Any], needle: str) -> int:
    """Rank how well *record* matches the (already-lowercased) search *needle*.

    Used as the primary sort key in ``_handle_query`` so that canonical hits
    aren't hidden below the default ``limit=25`` when a broad term like
    ``"cost"`` produces dozens of substring matches. Alphabetical by
    ``field_id`` is the tiebreaker (applied as the secondary key by the
    caller), so order is fully deterministic within each tier.

    Tiers (lower sorts first):
        0 — exact match on ``field_id`` or ``display_name``
        1 — either starts with *needle* (prefix match)
        2 — substring hit (the fallback; the pool is already pre-filtered
            so every record will match at least at this tier)
    """
    fid = record.get("field_id", "").lower()
    dname = record.get("display_name", "").lower()
    if needle == fid or needle == dname:
        return 0
    if fid.startswith(needle) or dname.startswith(needle):
        return 1
    return 2


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
    # P1.1: when a search term is present, rank-then-alphabetize so canonical
    # hits (e.g. ``metric.totalCost`` for search "cost") aren't hidden below the
    # default limit=25. Without search, keep the original pure-alphabetical
    # order (no disruption to non-search callers).
    if inp.search:
        needle = inp.search.lower()

        def _sort_key(r: Dict[str, Any]) -> tuple:
            return (_rank_search_hit(r, needle), r["field_id"])
    else:

        def _sort_key(r: Dict[str, Any]) -> tuple:
            return (r["field_id"],)

    paged = sorted(pool, key=_sort_key)[inp.offset : inp.offset + inp.limit]

    entries = [
        _record_to_entry(r, include_description=False, include_v3=inp.include_v3_mapping)
        for r in paged
    ]

    # P1.3: response-level co-field hint. Fires ONLY when the paged window
    # (not the full pool) contains at least one entry with non-empty
    # ``required_fields``. The hint points the agent at validate mode so
    # they get the precise required-co-field list in one call instead of
    # submit-fail-learn.
    hint_required = any(bool(e.required_fields) for e in entries)
    hint_message: Optional[str] = None
    if hint_required:
        hint_message = (
            "Some returned entries require co-fields (e.g. budgetCurrency.value). "
            "Use mode='validate' to confirm the required co-fields for your "
            "selection before submitting CreateReport."
        )

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
        hint_required_co_fields=hint_required,
        hint_message=hint_message,
    )
    return _serialize_with_byte_cap(response, drop=drop_set)


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
