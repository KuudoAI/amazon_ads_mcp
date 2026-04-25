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
    """
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
    return envelope


def _merge_http_meta(
    root: BaseException,
    explicit: dict[str, Any] | None,
) -> dict[str, Any] | None:
    """Auto-extract rate-limit headers from ``httpx.HTTPStatusError`` and
    merge with explicitly-provided ``http_meta``.

    Explicit caller-supplied values win on key collisions. This preserves
    test/integration override patterns while making the common path
    (translator pulls headers from the response) zero-config.
    """
    auto: dict[str, Any] = {}
    if isinstance(root, httpx.HTTPStatusError):
        from ..utils.http.rate_limit_headers import extract_rate_limit_meta

        auto = extract_rate_limit_meta(root.response)
    if not auto and not explicit:
        return None
    if not explicit:
        return auto
    if not auto:
        return explicit
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


def _classify(exc: BaseException) -> _Classification:
    # Order matters: more-specific Pydantic / httpx checks first, then the
    # AmazonAdsMCPError hierarchy (most-specific subclasses first), then
    # MCPError, then the catch-all.

    if _is_pydantic_validation_error(exc) or _is_fastmcp_validation_error(exc):
        return _classify_validation(exc)

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
        custom_hints: list[str] = []
        if isinstance(exc.details, dict):
            for h in exc.details.get("hints") or []:
                if isinstance(h, str) and h:
                    custom_hints.append(h)
        return _Classification(
            error_kind="mcp_input_validation",
            summary="Tool input validation failed.",
            details=[_detail_from_ads_validation_error(exc)],
            hints=custom_hints
            or ["Check required fields and input types in the tool schema."],
            error_code="INPUT_VALIDATION_FAILED",
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


def _hints_for_validation(
    details: list[dict[str, Any]],
    schema_field_names: list[str],
) -> list[str]:
    """Build specific hints from the validation details array.

    Specific hints first (so they appear at the top of the agent's view),
    generic boilerplate as fallback when the details don't match a known
    pattern. Hints emitted:

    - ``"Required field missing: 'X'"`` when issue text contains "required" or
      "missing"
    - ``"Unknown field 'X'. Did you mean 'Y'?"`` when issue text indicates
      an unexpected key and a close canonical match exists (Levenshtein ≤ 2
      against ``schema_field_names``)
    - ``"Unknown field 'X'. Valid fields: ['a','b',...]"`` when no close
      match found but the schema names are known
    """
    specific: list[str] = []
    for entry in details:
        if not isinstance(entry, dict):
            continue
        path = str(entry.get("path") or "").strip()
        issue_text = str(entry.get("issue") or "").lower()

        if not path:
            continue

        if "missing" in issue_text or "required" in issue_text or "field required" in issue_text:
            specific.append(f"Required field missing: '{path}'.")
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
            elif schema_field_names:
                preview = sorted(schema_field_names)[:8]
                specific.append(
                    f"Unknown field '{path}'. Valid fields: {preview}."
                )
            else:
                specific.append(f"Unknown field '{path}'.")

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
