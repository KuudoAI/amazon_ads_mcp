"""Cross-server error envelope translator (v1).

Translates internal Ads exceptions (``AmazonAdsMCPError`` hierarchy in
``exceptions.py``, ``MCPError`` with ``ErrorCategory`` in ``utils/errors.py``,
plus stdlib exceptions) into the v1 envelope shape defined in
``openbridge-mcp/CONTRACT.md``.

Design intent:

- The translator runs at the MCP tool-call boundary. Internal callers of
  ``MCPError`` and ``AmazonAdsMCPError`` are unaffected.
- Every ``ErrorCategory`` value has an explicit mapping; no implicit
  fallthrough. New members of the enum require an explicit mapping update.
- ``AmazonAdsMCPError`` subclasses are mapped by class (most-specific first)
  rather than by string code, so renaming the underlying ``code`` attribute
  cannot silently change the contract.
- ``ENVELOPE_VERSION`` is exposed as a module-level constant so the
  ``get_envelope_contract`` builtin tool can publish the version.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from ..exceptions import (
    AmazonAdsMCPError,
    APIError,
    AuthenticationError,
    ConfigurationError,
    RateLimitError,
    SamplingError,
    TimeoutError as AdsTimeoutError,
    ToolExecutionError,
    TransformError,
    ValidationError as AdsValidationError,
)
from ..utils.errors import ErrorCategory, MCPError

#: Cross-server envelope contract version. See openbridge-mcp/CONTRACT.md.
ENVELOPE_VERSION = 1

#: Subset of the master taxonomy this server emits. Closed list.
SUPPORTED_ERROR_KINDS: tuple[str, ...] = (
    "mcp_input_validation",
    "ads_api_http",
    "auth_error",
    "rate_limited",
    "internal_error",
)

#: Envelope keys required by the v1 contract (mirror SP's ``_ENVELOPE_KEYS``
#: shape). Used by :func:`is_envelope_text` for idempotent passthrough.
_ENVELOPE_KEYS: frozenset[str] = frozenset({
    "error_kind",
    "tool",
    "summary",
    "details",
    "hints",
    "examples",
    "error_code",
    "retryable",
})


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def is_envelope_text(text: str) -> bool:
    """Return True when ``text`` is already a v1 envelope JSON payload."""
    try:
        parsed = json.loads(text)
    except (TypeError, ValueError):
        return False
    return isinstance(parsed, dict) and _ENVELOPE_KEYS.issubset(parsed.keys())


def envelope_to_json(envelope: dict[str, Any]) -> str:
    """Serialize an envelope to stable compact JSON."""
    return json.dumps(envelope, ensure_ascii=True, separators=(",", ":"))


def build_envelope_from_exception(
    exc: BaseException,
    tool_name: str | None,
    *,
    normalized: list[dict[str, Any]] | None = None,
    http_meta: dict[str, Any] | None = None,
    emit_legacy_error_kind: bool = False,
    tool_args: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Translate an exception into a v1 envelope dict.

    :param exc: The exception to translate. May be wrapped via ``__cause__``
        / ``__context__``; the translator walks the chain to find the root.
    :param tool_name: The MCP tool name that failed. ``None`` becomes
        ``"unknown_tool"``.
    :param normalized: Optional pre-flight normalization events captured by
        the sidecar middleware. Surface in ``_meta.normalized``.
    :param http_meta: Optional upstream HTTP metadata captured during the
        failing call (``rate_limit`` block, ``retry_after_seconds``,
        ``warnings``). Surface in ``_meta``.
    :param emit_legacy_error_kind: If True, include ``legacy_error_kind`` in
        the envelope carrying the prior taxonomy value (one-release migration
        window). Default False.
    :param tool_args: Optional original tool arguments. Round 13 C-pre: used
        for retroactive catalog-aware hint enrichment when the failing tool
        is ``AdsApiv1CreateReport`` (the catalog already knows which v1
        field combinations are incompatible — surface that knowledge in
        the envelope so the agent gets the same guidance ``mode='validate'``
        would have given).
    """
    # Round 8: when the exception's message text carries an inner v1
    # envelope (Code Mode sandbox bridge → MontyRuntimeError → outer
    # RuntimeError chain), surface the inner envelope rather than
    # wrapping it. Otherwise every ``execute(call_tool(...))`` failure
    # shows as ``internal_error`` / ``sandbox_runtime`` and the inner
    # mcp_input_validation / ads_api_http / etc. is buried in
    # ``details[0].issue`` as a string.
    inner = _extract_inner_envelope(exc)
    if inner is not None:
        if emit_legacy_error_kind:
            # Preserve legacy taxonomy from the inner envelope if present
            inner = dict(inner)
        return inner
    # Classify by the OUTER exception first so typed re-raises (e.g.
    # ``raise AdsValidationError(...) from ValueError(...)``) are routed by
    # the wrapper's class, not the underlying cause. Fall back to the root
    # cause when the outer exception isn't a known type.
    classified = _try_classify_known_type(exc)
    if classified is None:
        root_for_classification: BaseException = _find_root_cause(exc)
        classified = _classify(root_for_classification)
    else:
        root_for_classification = exc
    classification = classified
    tool = tool_name or "unknown_tool"
    # Header auto-extraction: walk to a root that is an HTTPStatusError if
    # one exists in the chain, regardless of how we classified.
    root_for_http_meta = (
        root_for_classification
        if isinstance(root_for_classification, httpx.HTTPStatusError)
        else _find_root_cause(exc)
    )
    merged_http_meta = _merge_http_meta(root_for_http_meta, http_meta)
    envelope = _build_envelope(
        error_kind=classification.error_kind,
        tool=tool,
        summary=classification.summary,
        details=classification.details,
        hints=classification.hints,
        examples=[],
        error_code=classification.error_code,
        retryable=classification.retryable,
        normalized=normalized,
        http_meta=merged_http_meta,
    )
    if emit_legacy_error_kind and classification.legacy_error_kind is not None:
        envelope["legacy_error_kind"] = classification.legacy_error_kind
    # Round 6 #2: single envelope-level field-name promotion pass.
    # Runs AFTER classification regardless of which classifier built
    # the envelope. New classification paths get hint quality for free.
    _promote_field_signals_into_hints(envelope)
    # Round 13 C-pre (gaps 1+2): when AdsApiv1CreateReport returned
    # an upstream HTTP error AND we have the original request body,
    # retroactively run the catalog validator and surface
    # incompatible_pairs / missing_required as additional hints. The
    # catalog already knows what mode="validate" would have caught;
    # this gives the agent that same guidance after the call has
    # already failed, instead of forcing a separate validate retry.
    #
    # Includes auth_error because upstream 401/403 on a CreateReport
    # call still surfaces from the request body the agent constructed
    # — and the catalog can still flag bad fields in query.fields[].
    # When the auth error is unrelated to fields, the catalog hints
    # are no-ops; the agent gets no false guidance.
    if (
        tool_args
        and isinstance(tool_args, dict)
        and tool_name
        and (
            "CreateReport" in tool_name
            # Round 14 Phase A: low-impact hardening for the
            # pathological hybrid-body case where an agent constructs
            # CreateReport-shaped args against QueryAdvertiserAccount.
            # ``_enrich_with_catalog_validate`` walks for
            # ``query.fields[]`` and silently no-ops when absent — so
            # widening the gate to QAA costs nothing on normal calls
            # and steers the agent toward the right endpoint when the
            # body is misshapen.
            or "QueryAdvertiserAccount" in tool_name
        )
        and classification.error_kind
        in ("ads_api_http", "ads_api_client", "auth_error")
    ):
        _enrich_with_catalog_validate(envelope, tool_args)
    return envelope


def _enrich_with_catalog_validate(
    envelope: dict[str, Any], tool_args: dict[str, Any]
) -> None:
    """Round 13 C-pre — retroactive catalog validate on CreateReport 4xx.

    Extracts the request's ``query.fields[]`` (and ``reports[].query.fields[]``)
    and runs ``mode="validate"`` against the catalog. Surface
    ``incompatible_pairs``, ``missing_required``, and
    ``unknown_fields`` (with catalog suggestions) as additional hints
    on the envelope. Best-effort; never raises.
    """
    try:
        # Walk the request for query.fields[] in any of the three shapes:
        #
        #   (a) FastMCP-flattened OpenAPI body — fields at top level:
        #       tool_args = {"accessRequestedAccounts": [...], "reports": [...]}
        #   (b) Hand-wrapped {"body": {...}} from agents that read the docs
        #       too literally and nest the body under a "body" key
        #   (c) Top-level "query" key (older shape variants)
        #
        # Cover all three so retroactive enrichment works regardless of
        # how the caller constructed the request.
        candidate_field_lists: list[list[str]] = []

        def _walk(container: Any) -> None:
            if not isinstance(container, dict):
                return
            reports = container.get("reports")
            if isinstance(reports, list):
                for r in reports:
                    if isinstance(r, dict):
                        q = r.get("query")
                        if isinstance(q, dict):
                            f = q.get("fields")
                            if isinstance(f, list):
                                candidate_field_lists.append(
                                    [str(x) for x in f if isinstance(x, str)]
                                )
            top_q = container.get("query")
            if isinstance(top_q, dict):
                f = top_q.get("fields")
                if isinstance(f, list):
                    candidate_field_lists.append(
                        [str(x) for x in f if isinstance(x, str)]
                    )

        # (a) flattened — walk tool_args directly
        _walk(tool_args if isinstance(tool_args, dict) else None)
        # (b) wrapped — walk tool_args.get("body")
        if isinstance(tool_args, dict):
            _walk(tool_args.get("body"))
        if not candidate_field_lists:
            return

        from ..tools.report_fields_v1_handler import handle as rf_handle

        merged_unknown: list[str] = []
        merged_missing: dict[str, list[str]] = {}
        merged_pairs: list[tuple[str, str]] = []
        merged_suggestions: dict[str, list[str]] = {}
        for fields in candidate_field_lists:
            try:
                resp = rf_handle(
                    mode="validate",
                    operation="allv1_AdsApiv1CreateReport",
                    validate_fields=fields,
                )
                payload = resp.model_dump(exclude_none=True)
                for k in payload.get("unknown_fields") or []:
                    if k not in merged_unknown:
                        merged_unknown.append(k)
                for k, v in (payload.get("missing_required") or {}).items():
                    merged_missing.setdefault(k, list(v))
                for pair in payload.get("incompatible_pairs") or []:
                    pt = tuple(pair) if isinstance(pair, (list, tuple)) else None
                    if pt and pt not in merged_pairs:
                        merged_pairs.append(pt)
                for k, v in (payload.get("suggested_replacements") or {}).items():
                    merged_suggestions.setdefault(k, list(v))
            except Exception:  # pragma: no cover - defensive
                continue

        new_hints: list[str] = []
        if merged_pairs:
            pair_strs = [f"{a} + {b}" for a, b in merged_pairs[:5]]
            new_hints.append(
                f"v1 catalog flags incompatible field pairs in your "
                f"query.fields[]: {'; '.join(pair_strs)}. Drop one of "
                f"each pair before retrying."
            )
        if merged_missing:
            sample = next(iter(merged_missing.items()))
            new_hints.append(
                f"v1 catalog flags missing required field(s): "
                f"{sample[0]} requires {sample[1]}. Add the required "
                f"co-fields to query.fields[]."
            )
        if merged_unknown:
            # Round 13 Phase C-4: re-derive suggestions through the
            # curated-table path so semantic v1↔v3 mappings outrank
            # substring noise (keyword.text → target.value, etc.).
            # Pass the request body so applies_when filters fire.
            from ..tools.report_fields_v1_handler import (
                catalog_suggestions_for,
            )

            # Build context body from tool_args for applies_when.
            ctx_body: dict[str, Any] = {}
            if isinstance(tool_args, dict):
                # Top-level adProduct is rare; usually it lives inside
                # reports[*].query or filter shapes. Surface whatever
                # is at the top level for the simple SPONSORED_PRODUCTS
                # check; richer matching can come later.
                if "adProduct" in tool_args:
                    ctx_body["adProduct"] = tool_args["adProduct"]
                # Walk reports[*] for any adProduct hint.
                reports = tool_args.get("reports")
                if isinstance(reports, list):
                    for r in reports:
                        if isinstance(r, dict):
                            ap = r.get("adProduct") or (
                                (r.get("query") or {}).get("adProduct")
                            )
                            if ap:
                                ctx_body.setdefault("adProduct", ap)

            # Round 13 follow-up: the prior ``[:3]`` cap silently
            # dropped suggestions for the 4th+ unknown field
            # (alphabetical sort meant ``metric.spend`` was excluded
            # when keyword.* + metric.cost + metric.spend all appeared
            # together). Now we surface a suggestion line for EVERY
            # unknown that has a catalog match — agents see the full
            # rewrite plan in one envelope. Cap kept at 8 to bound
            # hint length on pathological calls with dozens of bad
            # fields; real-world calls have 1–5.
            unknown_sorted = sorted(merged_unknown)
            unknown_summary = ", ".join(unknown_sorted[:8])
            sugg_lines = []
            for bad in unknown_sorted[:8]:
                # Prefer curated-table-aware suggestions over the
                # validate-mode token-only output.
                sugg = catalog_suggestions_for(bad, body=ctx_body or None)
                if not sugg:
                    sugg = merged_suggestions.get(bad) or []
                if sugg:
                    sugg_lines.append(f"{bad} → {', '.join(sugg)}")
            sugg_clause = (
                f" Did you mean: {'; '.join(sugg_lines)}?"
                if sugg_lines
                else ""
            )
            new_hints.append(
                f"v1 catalog rejects unknown field(s): "
                f"{unknown_summary}.{sugg_clause}"
            )
        new_hints.append(
            "Pre-flight with `report_fields(mode=\"validate\", "
            "operation=\"allv1_AdsApiv1CreateReport\", "
            "validate_fields=[...])` to catch this before the call."
        )

        existing_hints = envelope.get("hints") or []
        envelope["hints"] = list(existing_hints) + new_hints
    except Exception:  # pragma: no cover - defensive
        return


def _merge_http_meta(
    root: BaseException,
    explicit: dict[str, Any] | None,
) -> dict[str, Any] | None:
    """Auto-extract rate-limit headers from ``httpx.HTTPStatusError``,
    fall back to the per-call context-var, and merge with
    explicitly-provided ``http_meta``.

    Round 5 #2: typed exceptions (e.g. ``RateLimitError``) raised after
    the HTTP client captured rate-limit headers don't carry the response
    object — but the context-var ``_LAST_HTTP_META`` populated by
    ``AuthenticatedClient.send`` still has the data. Pull from there as
    a fallback so error envelopes carry ``_meta.rate_limit`` regardless
    of which exception type ultimately fires.

    Precedence (highest to lowest): explicit ``http_meta`` arg →
    auto-extracted HTTPStatusError response headers → context-var
    capture.
    """
    from ..utils.http.rate_limit_headers import (
        extract_rate_limit_meta,
        get_last_http_meta,
    )

    auto: dict[str, Any] = {}
    if isinstance(root, httpx.HTTPStatusError):
        auto = extract_rate_limit_meta(root.response)
    if not auto:
        # Fallback: per-call context-var captured by the HTTP client.
        captured = get_last_http_meta()
        if captured:
            auto = dict(captured)
    if not auto and not explicit:
        return None
    if not explicit:
        return auto
    if not auto:
        return explicit
    # Explicit wins on key collisions; auto fills in missing keys
    # (including individual sub-keys of ``rate_limit`` when explicit
    # only specifies some of them).
    return {**auto, **explicit}


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


class _Classification:
    __slots__ = (
        "error_kind",
        "summary",
        "details",
        "hints",
        "error_code",
        "retryable",
        "legacy_error_kind",
    )

    def __init__(
        self,
        *,
        error_kind: str,
        summary: str,
        details: list[dict[str, Any]],
        hints: list[str],
        error_code: str,
        retryable: bool,
        legacy_error_kind: str | None = None,
    ) -> None:
        self.error_kind = error_kind
        self.summary = summary
        self.details = details
        self.hints = hints
        self.error_code = error_code
        self.retryable = retryable
        self.legacy_error_kind = legacy_error_kind


def _extract_inner_envelope(exc: BaseException) -> dict[str, Any] | None:
    """Round 8: walk ``exc.__cause__`` / ``__context__`` and message
    text looking for an embedded v1 envelope. Returns the parsed
    envelope dict when one is found, else ``None``.

    Patterns handled:
    - ``RuntimeError("ToolError: <envelope_json>")`` — Code Mode bridge
    - ``RuntimeError("<envelope_json>")`` — bare envelope as message
    - ``MontyRuntimeError("RuntimeError: ToolError: <envelope_json>")``
    - Same shapes nested in ``__cause__`` / ``__context__``

    Otherwise an ``execute(call_tool(...))`` failure shows the outer
    middleware's ``internal_error`` wrapper and the inner v1 envelope is
    buried in ``details[0].issue`` as a string — defeating the
    cross-server contract.
    """
    visited: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in visited:
        visited.add(id(current))
        text = str(current)
        if text and "_envelope_version" in text:
            envelope = _try_parse_v1_envelope_from_text(text)
            if envelope is not None:
                return envelope
        nxt = current.__cause__ or current.__context__
        if not isinstance(nxt, BaseException):
            return None
        current = nxt
    return None


def _try_parse_v1_envelope_from_text(text: str) -> dict[str, Any] | None:
    """Pull the first balanced JSON object containing
    ``"_envelope_version": 1`` out of a message string and validate it
    against the v1 envelope shape.
    """
    if "_envelope_version" not in text:
        return None
    n = len(text)
    i = 0
    while i < n:
        if text[i] != "{":
            i += 1
            continue
        depth = 0
        j = i
        in_string = False
        escape = False
        while j < n:
            ch = text[j]
            if in_string:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == '"':
                    in_string = False
            else:
                if ch == '"':
                    in_string = True
                elif ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        candidate = text[i : j + 1]
                        try:
                            parsed = json.loads(candidate)
                        except (TypeError, ValueError):
                            parsed = None
                        if (
                            isinstance(parsed, dict)
                            and parsed.get("_envelope_version") == 1
                            and _ENVELOPE_KEYS.issubset(parsed.keys())
                        ):
                            return parsed
                        i = j + 1
                        break
            j += 1
        else:
            return None
        if j >= n:
            return None
    return None


def _try_classify_known_type(exc: BaseException) -> _Classification | None:
    """Walk the cause chain of ``exc`` looking for the first exception
    whose type we recognize, and classify by that.

    Rationale: FastMCP wraps tool exceptions in its own ``ToolError`` before
    our middleware sees them, so the OUTER exception is rarely a typed
    exception we care about. The bare ``_find_root_cause`` walker drills
    past our typed re-raises (``raise AdsValidationError(...) from ValueError(...)``)
    all the way to the underlying ``ValueError`` and routes us into the
    catch-all. This walker stops at the first recognized type instead.

    Returns ``None`` when no link in the chain is recognized.
    """
    current: BaseException | None = exc
    visited: set[int] = set()
    while current is not None and id(current) not in visited:
        visited.add(id(current))
        if (
            _is_pydantic_validation_error(current)
            or _is_fastmcp_validation_error(current)
            or isinstance(current, httpx.HTTPStatusError)
            or isinstance(
                current,
                (
                    RateLimitError,
                    AuthenticationError,
                    AdsTimeoutError,
                    APIError,
                    AdsValidationError,
                    ConfigurationError,
                    SamplingError,
                    TransformError,
                    ToolExecutionError,
                    AmazonAdsMCPError,
                    MCPError,
                ),
            )
        ):
            return _classify(current)
        nxt = current.__cause__ or current.__context__
        if not isinstance(nxt, BaseException):
            return None
        current = nxt
    return None


def _is_fastmcp_not_found_error(exc: BaseException) -> bool:
    try:
        from fastmcp.exceptions import NotFoundError as FastMCPNotFoundError
    except Exception:  # pragma: no cover - defensive
        return False
    return isinstance(exc, FastMCPNotFoundError)


def _classify(exc: BaseException) -> _Classification:
    # Order matters: more-specific Pydantic / httpx checks first, then the
    # AmazonAdsMCPError hierarchy (most-specific subclasses first), then
    # MCPError, then the catch-all.

    if _is_pydantic_validation_error(exc) or _is_fastmcp_validation_error(exc):
        return _classify_validation(exc)

    if _is_fastmcp_not_found_error(exc):
        # Phase 2 (Round 11): unknown tool name. Re-routed from
        # the catch-all (which previously surfaced as ``internal_error``
        # / ``ads_api_client``) per ``openbridge-mcp/CONTRACT.md``.
        # Round 12 SP-1: dedicated ``tool_not_found`` error_kind
        # (was ``mcp_input_validation``). Additive taxonomy entry; agents
        # that branch on ``error_code`` (``TOOL_NOT_FOUND``) are unaffected.
        # The call never reached the upstream API; this is purely an
        # MCP-side mistake.
        return _Classification(
            error_kind="tool_not_found",
            summary="Tool is not registered on this server.",
            details=[_detail_from_message(exc)],
            hints=[
                "Search the tool catalog (e.g. via the 'search' meta-tool) "
                "to find the correct tool name.",
                "Tool names are case-sensitive and may carry namespace prefixes.",
            ],
            error_code="TOOL_NOT_FOUND",
            retryable=False,
            legacy_error_kind="NOT_FOUND",
        )

    if isinstance(exc, httpx.HTTPStatusError):
        return _classify_http_status(exc)

    # AmazonAdsMCPError subclasses — order specific → general
    if isinstance(exc, RateLimitError):
        return _Classification(
            error_kind="rate_limited",
            summary="Amazon Ads API rate limit exceeded.",
            details=[_detail_from_message(exc)],
            hints=["Back off before retrying. Use Retry-After if provided."],
            # Standardized cross-server vocabulary: per-server HTTP code
            # for upstream-origin rate limiting (matches SP's pattern).
            error_code="ADS_API_HTTP_429",
            retryable=True,
            legacy_error_kind="API_ERROR",
        )

    if isinstance(exc, AuthenticationError):
        # Includes OAuthError, OAuthStateError, TokenError
        return _Classification(
            error_kind="auth_error",
            summary="Authentication failed for Amazon Ads API.",
            details=[_detail_from_message(exc)],
            hints=[
                "Check credentials and refresh token validity.",
                "Re-authorize the active identity if expired.",
            ],
            error_code=getattr(exc, "code", "AUTHENTICATION_ERROR"),
            retryable=False,
            legacy_error_kind=getattr(exc, "code", "AUTHENTICATION_ERROR"),
        )

    if isinstance(exc, (AdsTimeoutError, APIError)):
        status = getattr(exc, "status_code", None)
        retryable = bool(status is None or status >= 500 or status == 408)
        code_suffix = str(status) if status is not None else "TIMEOUT"
        return _Classification(
            error_kind="ads_api_http",
            summary=(
                f"Amazon Ads API request failed with HTTP {status}."
                if status is not None
                else "Amazon Ads API request timed out."
            ),
            details=[_detail_from_message(exc)],
            hints=[
                "Inspect details for upstream error codes and messages.",
                "Retry idempotent operations after backoff for 5xx and timeouts.",
            ],
            error_code=f"ADS_API_HTTP_{code_suffix}",
            retryable=retryable,
            legacy_error_kind=getattr(exc, "code", "API_ERROR"),
        )

    if isinstance(exc, AdsValidationError):
        # Ads' own pre-flight validation (not the upstream's 4xx). Tools may
        # attach custom hints under ``exc.details["hints"]`` (list of str) so
        # tool-specific guidance can flow through without the translator
        # knowing about every tool. Fall back to the generic hint when none
        # are provided.
        # Phase 1 (Round 11): the new ``SchemaValidationMiddleware``
        # raises ``AdsValidationError`` with ``code`` set to a canonical
        # ``SCHEMA_*`` value (e.g. ``SCHEMA_MAX_ITEMS``) per
        # ``openbridge-mcp/schemas/jsonschema_error_codes.json``. Surface
        # that code on the envelope. Legacy callers using the bare
        # ``ValidationError`` default code ``VALIDATION_ERROR`` fall back
        # to ``INPUT_VALIDATION_FAILED``.
        custom_hints: list[str] = []
        if isinstance(exc.details, dict):
            for h in exc.details.get("hints") or []:
                if isinstance(h, str) and h:
                    custom_hints.append(h)
        raw_code = getattr(exc, "code", None) or ""
        envelope_error_code = (
            raw_code
            if raw_code
            and raw_code != "VALIDATION_ERROR"
            and raw_code.startswith("SCHEMA_")
            else "INPUT_VALIDATION_FAILED"
        )
        return _Classification(
            error_kind="mcp_input_validation",
            summary="Tool input validation failed.",
            details=[_detail_from_ads_validation_error(exc)],
            hints=custom_hints
            or ["Check required fields and input types in the tool schema."],
            error_code=envelope_error_code,
            retryable=False,
            legacy_error_kind=getattr(exc, "code", "VALIDATION_ERROR"),
        )

    if isinstance(exc, (ConfigurationError, SamplingError, TransformError)):
        return _Classification(
            error_kind="internal_error",
            summary="Server-side error before completing the upstream call.",
            details=[_detail_from_message(exc)],
            hints=["Inspect server logs; this is not a client-fixable error."],
            error_code=getattr(exc, "code", "INTERNAL_ERROR"),
            retryable=False,
            legacy_error_kind=getattr(exc, "code", "INTERNAL_ERROR"),
        )

    if isinstance(exc, ToolExecutionError):
        # Wraps an original; if we can introspect it, re-classify; else
        # treat as internal.
        original = getattr(exc, "original_error", None)
        if isinstance(original, BaseException) and original is not exc:
            return _classify(original)
        return _Classification(
            error_kind="internal_error",
            summary="Tool execution failed before reaching the upstream API.",
            details=[_detail_from_message(exc)],
            hints=["Inspect server logs for the wrapped exception."],
            error_code=getattr(exc, "code", "TOOL_EXECUTION_ERROR"),
            retryable=False,
            legacy_error_kind=getattr(exc, "code", "TOOL_EXECUTION_ERROR"),
        )

    if isinstance(exc, AmazonAdsMCPError):
        # Catch-all for AmazonAdsMCPError subclasses not handled above
        return _Classification(
            error_kind="internal_error",
            summary="Amazon Ads MCP error.",
            details=[_detail_from_message(exc)],
            hints=["Inspect server logs for the underlying exception."],
            error_code=getattr(exc, "code", "INTERNAL_ERROR"),
            retryable=False,
            legacy_error_kind=getattr(exc, "code", "INTERNAL_ERROR"),
        )

    if isinstance(exc, MCPError):
        return _classify_mcp_error(exc)

    # bare Exception → internal_error
    return _Classification(
        error_kind="internal_error",
        summary="Unhandled server-side exception.",
        details=[_detail_from_message(exc)],
        hints=["Inspect server logs."],
        error_code="INTERNAL_ERROR",
        retryable=False,
        legacy_error_kind=None,
    )


def _classify_mcp_error(exc: MCPError) -> _Classification:
    """Map every ErrorCategory member explicitly. No fallthrough."""
    cat = exc.category
    legacy = cat.value  # the lowercase string used by the existing model

    if cat in (ErrorCategory.AUTHENTICATION, ErrorCategory.PERMISSION):
        return _Classification(
            error_kind="auth_error",
            summary=str(exc.user_message or exc.message),
            details=_details_from_mcp_error(exc),
            hints=["Check credentials and active identity scope."],
            error_code=f"AUTH_{cat.name}",
            retryable=False,
            legacy_error_kind=legacy,
        )

    if cat is ErrorCategory.VALIDATION:
        return _Classification(
            error_kind="mcp_input_validation",
            summary=str(exc.user_message or exc.message),
            details=_details_from_mcp_error(exc),
            hints=["Check required fields and input types in the tool schema."],
            error_code="INPUT_VALIDATION_FAILED",
            retryable=False,
            legacy_error_kind=legacy,
        )

    if cat in (
        ErrorCategory.NETWORK,
        ErrorCategory.EXTERNAL_SERVICE,
        ErrorCategory.NOT_FOUND,
    ):
        retryable = cat is not ErrorCategory.NOT_FOUND
        return _Classification(
            error_kind="ads_api_http",
            summary=str(exc.user_message or exc.message),
            details=_details_from_mcp_error(exc),
            hints=["Inspect details for upstream error codes and messages."],
            error_code=f"ADS_API_HTTP_{exc.status_code or cat.name}",
            retryable=retryable,
            legacy_error_kind=legacy,
        )

    if cat is ErrorCategory.RATE_LIMIT:
        return _Classification(
            error_kind="rate_limited",
            summary=str(exc.user_message or exc.message),
            details=_details_from_mcp_error(exc),
            hints=["Back off before retrying."],
            error_code="ADS_API_HTTP_429",
            retryable=True,
            legacy_error_kind=legacy,
        )

    if cat in (ErrorCategory.INTERNAL, ErrorCategory.DATABASE):
        return _Classification(
            error_kind="internal_error",
            summary=str(exc.user_message or exc.message),
            details=_details_from_mcp_error(exc),
            hints=["Inspect server logs."],
            error_code=cat.name,
            retryable=False,
            legacy_error_kind=legacy,
        )

    # Unknown category — fail loudly so a future ErrorCategory member that
    # isn't mapped above is caught by tests, not silently classified as
    # internal_error.
    raise NotImplementedError(
        f"ErrorCategory.{cat.name} has no explicit mapping in _classify_mcp_error. "
        "Add the mapping in middleware/error_envelope.py and update the contract."
    )


# ---------------------------------------------------------------------------
# Pydantic / FastMCP validation
# ---------------------------------------------------------------------------


def _is_pydantic_validation_error(exc: BaseException) -> bool:
    try:
        from pydantic import ValidationError as PydanticValidationError
    except ImportError:  # pragma: no cover
        return False
    return isinstance(exc, PydanticValidationError)


def _is_fastmcp_validation_error(exc: BaseException) -> bool:
    try:
        from fastmcp.exceptions import ValidationError as FastMCPValidationError
    except ImportError:  # pragma: no cover
        return False
    return isinstance(exc, FastMCPValidationError)


def _classify_validation(exc: BaseException) -> _Classification:
    details = _parse_validation_details(exc)
    schema_field_names = _extract_schema_field_names(exc)
    hints = _hints_for_validation(details, schema_field_names)
    return _Classification(
        error_kind="mcp_input_validation",
        summary="Tool input validation failed.",
        details=details,
        hints=hints,
        error_code="INPUT_VALIDATION_FAILED",
        retryable=False,
        legacy_error_kind="validation",
    )


def _extract_schema_field_names(exc: BaseException) -> list[str]:
    """Pull canonical field names from a Pydantic validation error so we
    can run did-you-mean against them.

    Pydantic v2 doesn't expose the model directly on the exception. We try
    in priority order:

    1. ``exc.model`` — present on some Pydantic versions / paths
    2. Walk ``BaseModel.__subclasses__()`` looking for a class whose
       ``__name__`` matches ``exc.title``. Fragile-but-cheap; covers the
       most common case (named Pydantic models in the application).

    Returns ``[]`` when no field names can be resolved (caller falls back
    to generic hints).
    """
    try:
        from pydantic import BaseModel, ValidationError as _PydanticVE
    except ImportError:  # pragma: no cover
        return []
    if not isinstance(exc, _PydanticVE):
        return []
    # Path 1: direct model attribute
    model = getattr(exc, "model", None)
    if model is not None:
        fields = getattr(model, "model_fields", None) or {}
        if isinstance(fields, dict) and fields:
            return list(fields.keys())
    # Path 2: title → walk subclasses (Pydantic v2)
    title = getattr(exc, "title", None)
    if isinstance(title, str) and title:
        for cls in _walk_subclasses(BaseModel):
            if cls.__name__ == title:
                fields = getattr(cls, "model_fields", None) or {}
                if isinstance(fields, dict) and fields:
                    return list(fields.keys())
                break
    return []


def _walk_subclasses(root: type) -> list[type]:
    """Depth-first walk of ``type.__subclasses__`` returning all descendants."""
    out: list[type] = []
    stack: list[type] = list(root.__subclasses__())
    seen: set[int] = set()
    while stack:
        cls = stack.pop()
        if id(cls) in seen:
            continue
        seen.add(id(cls))
        out.append(cls)
        stack.extend(cls.__subclasses__())
    return out


#: Trailing characters that appear in upstream-supplied ``details.path``
#: values and must be stripped before formatting field names into hints.
_PATH_TRAILING_JUNK = " \t\n\r;,.:!?\"'"


def _sanitize_path(path: str) -> str:
    """Strip trailing punctuation / quotes / whitespace from a
    path string before it's formatted into a hint.
    """
    if not isinstance(path, str):
        return ""
    cleaned = path.strip(_PATH_TRAILING_JUNK)
    if len(cleaned) >= 2 and cleaned[0] == cleaned[-1] and cleaned[0] in ("'", '"'):
        cleaned = cleaned[1:-1].strip(_PATH_TRAILING_JUNK)
    return cleaned


def _promote_field_signals_into_hints(envelope: dict[str, Any]) -> None:
    """Single envelope-level pass that promotes ``details.path`` into
    specific hints when ``details[*].issue`` carries field-level signals.

    Runs once at the end of ``build_envelope_from_exception`` regardless
    of which classifier built the envelope. Pydantic validation,
    upstream HTTP errors, MCPError-typed exceptions, and bare
    exceptions all benefit. Mirrors the SP implementation so cross-
    server agent code sees identical hint shapes.

    - "Required field missing: 'X'" when issue suggests missing/required
    - "Unknown field 'X'" when issue suggests extra/unexpected/
      forbidden/not-permitted

    Field names are sanitized via :func:`_sanitize_path` so artifacts
    like ``"reportTypes;"`` don't leak into agent-facing text.
    """
    details = envelope.get("details") or []
    if not isinstance(details, list):
        return
    promoted: list[str] = []
    seen_paths: set[str] = set()
    for entry in details:
        if not isinstance(entry, dict):
            continue
        raw_path = entry.get("path")
        if not isinstance(raw_path, str):
            continue
        path = _sanitize_path(raw_path)
        if not path or path in seen_paths:
            continue
        issue_text = str(entry.get("issue") or "").lower()
        if (
            "missing" in issue_text
            or "required" in issue_text
            or "field required" in issue_text
        ):
            promoted.append(f"Required field missing: '{path}'.")
            seen_paths.add(path)
            continue
        if (
            "extra" in issue_text
            or "unexpected" in issue_text
            or "not permitted" in issue_text
            or "forbidden" in issue_text
            or "unknown" in issue_text
        ):
            promoted.append(f"Unknown field '{path}'.")
            seen_paths.add(path)
    if not promoted:
        return
    existing_hints = envelope.get("hints") or []
    if not isinstance(existing_hints, list):
        existing_hints = []
    envelope["hints"] = promoted + [h for h in existing_hints if h not in promoted]


def _hints_for_validation(
    details: list[dict[str, Any]],
    schema_field_names: list[str],
) -> list[str]:
    """Generic guidance for input validation rejections.

    Field-name promotion ("Required field missing: 'X'", etc.) is
    handled by the consolidated envelope-level pass
    :func:`_promote_field_signals_into_hints` so it fires regardless of
    which classifier built the envelope. This helper only contributes
    the generic baseline plus the "Did you mean 'Y'?" suggestion when
    schema field names are known (the suggestion needs schema
    introspection that the envelope-level pass doesn't have access to).
    """
    specific: list[str] = []
    if schema_field_names:
        for entry in details:
            if not isinstance(entry, dict):
                continue
            path = str(entry.get("path") or "").strip()
            issue_text = str(entry.get("issue") or "").lower()
            if not path:
                continue
            if (
                "extra" in issue_text
                or "unexpected" in issue_text
                or "not permitted" in issue_text
                or "forbidden" in issue_text
            ):
                suggestion = _did_you_mean(path, schema_field_names)
                if suggestion:
                    specific.append(
                        f"Unknown field '{path}'. Did you mean '{suggestion}'?"
                    )

    fallback = [
        "Check required fields and input types in the tool schema.",
        "Use canonical schema field names (e.g., camelCase for v2/v3 endpoints).",
    ]
    return specific + fallback if specific else fallback


def _did_you_mean(needle: str, haystack: list[str]) -> str | None:
    """Return the closest canonical name in ``haystack`` within Levenshtein
    distance 2, or None when no good match exists.

    Comparisons are case-insensitive so PascalCase typos suggest the
    camelCase canonical (and vice-versa).
    """
    if not needle or not haystack:
        return None
    target = needle.lower()
    best: tuple[int, str] | None = None
    for candidate in haystack:
        d = _levenshtein(target, candidate.lower())
        if d > 2:
            continue
        if best is None or d < best[0]:
            best = (d, candidate)
    return best[1] if best else None


def _levenshtein(a: str, b: str) -> int:
    """Iterative Levenshtein distance with O(min(len)) memory."""
    if a == b:
        return 0
    if len(a) > len(b):
        a, b = b, a
    if not a:
        return len(b)
    prev = list(range(len(a) + 1))
    for i, cb in enumerate(b, start=1):
        curr = [i]
        for j, ca in enumerate(a, start=1):
            ins = curr[j - 1] + 1
            dele = prev[j] + 1
            sub = prev[j - 1] + (0 if ca == cb else 1)
            curr.append(min(ins, dele, sub))
        prev = curr
    return prev[-1]


def _parse_validation_details(exc: BaseException) -> list[dict[str, Any]]:
    try:
        from pydantic import ValidationError as PydanticValidationError
    except ImportError:  # pragma: no cover
        PydanticValidationError = None  # type: ignore[assignment]

    if PydanticValidationError is not None and isinstance(exc, PydanticValidationError):
        out: list[dict[str, Any]] = []
        for err in exc.errors():
            loc = ".".join(str(x) for x in err.get("loc", []))
            received = err.get("input")
            out.append(
                {
                    "path": loc,
                    "issue": err.get("msg", "Invalid value."),
                    "received_type": type(received).__name__,
                }
            )
        return out
    return [_detail_from_message(exc)]


# ---------------------------------------------------------------------------
# httpx HTTP status errors
# ---------------------------------------------------------------------------


def _classify_http_status(exc: httpx.HTTPStatusError) -> _Classification:
    status = exc.response.status_code
    is_retryable = status >= 500 or status in (408, 429)
    if status == 429:
        return _Classification(
            error_kind="rate_limited",
            summary=f"Amazon Ads API request failed with HTTP {status}.",
            details=_parse_http_details(exc.response),
            hints=["Rate limited by Amazon Ads; retry with backoff."],
            error_code=f"ADS_API_HTTP_{status}",
            retryable=True,
            legacy_error_kind="rate_limit",
        )
    return _Classification(
        error_kind="ads_api_http",
        summary=f"Amazon Ads API request failed with HTTP {status}.",
        details=_parse_http_details(exc.response),
        hints=["Inspect details for upstream error codes and messages."],
        error_code=f"ADS_API_HTTP_{status}",
        retryable=is_retryable,
        legacy_error_kind="external_service" if status >= 500 else "validation",
    )


def _parse_http_details(response: httpx.Response) -> list[dict[str, Any]]:
    try:
        body = response.json()
    except Exception:
        body = response.text
    if isinstance(body, dict):
        return [
            {
                "path": "",
                "issue": str(
                    body.get("message") or body.get("details") or body.get("error") or body
                ),
                "received_type": "dict",
            }
        ]
    if isinstance(body, list):
        return [
            {"path": str(i), "issue": str(item), "received_type": type(item).__name__}
            for i, item in enumerate(body)
        ]
    return [{"path": "", "issue": str(body) or "Upstream returned non-JSON body.", "received_type": "str"}]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _detail_from_message(exc: BaseException) -> dict[str, Any]:
    return {
        "path": "",
        "issue": str(exc) or exc.__class__.__name__,
        "received_type": exc.__class__.__name__,
    }


def _detail_from_ads_validation_error(exc: AdsValidationError) -> dict[str, Any]:
    field = exc.details.get("field", "") if isinstance(exc.details, dict) else ""
    return {
        "path": str(field),
        "issue": exc.message,
        "received_type": exc.__class__.__name__,
    }


def _details_from_mcp_error(exc: MCPError) -> list[dict[str, Any]]:
    details = exc.details if isinstance(exc.details, dict) else {}
    if not details:
        return [_detail_from_message(exc)]
    return [
        {
            "path": str(details.get("path", "") or details.get("field", "")),
            "issue": exc.message,
            "received_type": exc.__class__.__name__,
        }
    ]


def _find_root_cause(exc: BaseException) -> BaseException:
    current: BaseException = exc
    visited: set[int] = set()
    while True:
        obj_id = id(current)
        if obj_id in visited:
            return current
        visited.add(obj_id)
        nxt = current.__cause__ or current.__context__
        if isinstance(nxt, BaseException):
            current = nxt
            continue
        return current


def _build_envelope(
    *,
    error_kind: str,
    tool: str,
    summary: str,
    details: list[dict[str, Any]],
    hints: list[str],
    examples: list[Any],
    error_code: str,
    retryable: bool,
    normalized: list[dict[str, Any]] | None = None,
    http_meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    envelope: dict[str, Any] = {
        "error_kind": error_kind,
        "tool": tool,
        "summary": summary,
        "details": details,
        "hints": hints,
        "examples": examples,
        "error_code": error_code,
        "retryable": retryable,
        "_envelope_version": ENVELOPE_VERSION,
    }
    meta: dict[str, Any] = {}
    if normalized:
        meta["normalized"] = normalized
    if isinstance(http_meta, dict):
        rate_limit = http_meta.get("rate_limit")
        if isinstance(rate_limit, dict) and rate_limit:
            meta["rate_limit"] = rate_limit
        warnings = http_meta.get("warnings")
        if isinstance(warnings, list) and warnings:
            meta["warnings"] = warnings
        retry_after_seconds = http_meta.get("retry_after_seconds")
        if isinstance(retry_after_seconds, (int, float)):
            meta["retry_after_seconds"] = float(retry_after_seconds)
    if meta:
        envelope["_meta"] = meta
    return envelope
