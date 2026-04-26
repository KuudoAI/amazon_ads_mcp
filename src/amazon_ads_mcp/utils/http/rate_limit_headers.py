"""Amazon Ads rate-limit header parsing for the v1 envelope contract.

Translates upstream Amazon Ads API ``X-RateLimit-*`` and ``Retry-After``
headers into the wire shape consumed by the envelope translator and
``_meta`` builder.

Output format (matches ``openbridge-mcp/CONTRACT.md``):

::

    {
      "rate_limit": {
        "limit_per_second": float | str,
        "remaining":        float | str,
        "reset_at":         str
      },
      "retry_after_seconds": float
    }

Contract guarantee: only fields with parseable values are emitted; absent
or unparseable headers result in absent keys (never ``None``). Per-server
header names differ; the *output shape* is shared across servers.
"""

from __future__ import annotations

from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any, Optional

import httpx


#: Per-request capture of upstream rate-limit metadata for the in-flight tool
#: call. Set by the HTTP client after every successful response; read by the
#: meta-injection middleware to attach ``_meta.rate_limit`` to successful
#: tool responses. Cleared between calls.
_LAST_HTTP_META: ContextVar[Optional[dict[str, Any]]] = ContextVar(
    "ads_last_http_meta", default=None
)


def set_last_http_meta(meta: dict[str, Any] | None) -> None:
    """Capture HTTP meta for the in-flight call. ``None`` clears."""
    _LAST_HTTP_META.set(meta)


def get_last_http_meta() -> dict[str, Any] | None:
    """Return HTTP meta captured by the most recent upstream response."""
    return _LAST_HTTP_META.get()


def clear_last_http_meta() -> None:
    """Reset the captured HTTP meta. Call at the start of every tool call."""
    _LAST_HTTP_META.set(None)


def extract_rate_limit_meta(response: httpx.Response) -> dict[str, Any]:
    """Extract rate-limit and warning metadata from an upstream Amazon Ads
    API response.

    :param response: The httpx response to inspect.
    :returns: Dict with any of ``rate_limit``, ``retry_after_seconds``,
        ``warnings`` keys, populated only for parseable headers. Empty dict
        when none are present.
    """
    meta: dict[str, Any] = {}

    rate_limit = _parse_rate_limit_block(response)
    if rate_limit:
        meta["rate_limit"] = rate_limit

    retry_after = _parse_retry_after_seconds(response)
    if retry_after is not None:
        meta["retry_after_seconds"] = retry_after

    warnings = _parse_warning_headers(response)
    if warnings:
        meta["warnings"] = warnings

    return meta


def _parse_warning_headers(response: httpx.Response) -> list[dict[str, Any]]:
    """Parse upstream RFC 7234 ``Warning`` headers into the v1 contract shape.

    Each entry: ``{kind: "upstream_warning", summary, details: [], hints: []}``.
    Per-server appendices in ``openbridge-mcp/CONTRACT.md`` may layer
    domain-specific kinds (``cached_or_stale_data``,
    ``profile_scope_warning``, etc.) on top of this generic upstream form.
    """
    raw_values: list[str] = []
    if hasattr(response.headers, "get_list"):
        raw_values.extend(response.headers.get_list("warning"))
    else:
        single = response.headers.get("warning")
        if single is not None:
            raw_values.append(single)

    out: list[dict[str, Any]] = []
    for raw in raw_values:
        text = (raw or "").strip()
        if not text:
            continue
        out.append(
            {
                "kind": "upstream_warning",
                "summary": text,
                "details": [],
                "hints": [],
            }
        )
    return out


def _parse_rate_limit_block(response: httpx.Response) -> dict[str, Any]:
    """Parse the ``X-RateLimit-Limit`` family of headers."""
    block: dict[str, Any] = {}

    limit = _stripped(response.headers.get("x-ratelimit-limit"))
    remaining = _stripped(response.headers.get("x-ratelimit-remaining"))
    reset = _stripped(response.headers.get("x-ratelimit-reset"))

    if limit:
        block["limit_per_second"] = _try_float(limit)
    if remaining:
        block["remaining"] = _try_float(remaining)
    if reset:
        block["reset_at"] = reset
    return block


def _try_float(value: str) -> float | str:
    """Try to coerce ``value`` to float; on failure return the raw string."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return value


def _stripped(value: str | None) -> str | None:
    """Return ``value`` stripped, or ``None`` when empty/whitespace/missing."""
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _parse_retry_after_seconds(response: httpx.Response) -> float | None:
    """Parse the ``Retry-After`` header into seconds-from-now.

    Supports both forms allowed by RFC 7231:

    - delta-seconds (e.g. ``"30"``)
    - HTTP-date (e.g. ``"Fri, 25 Apr 2026 17:42:33 GMT"``)

    Past HTTP-dates clamp to ``0.0``. Unparseable values return ``None``.
    """
    raw = _stripped(response.headers.get("retry-after"))
    if not raw:
        return None
    if raw.isdigit():
        try:
            return max(0.0, float(raw))
        except (TypeError, ValueError):
            return None
    try:
        when = datetime.strptime(raw, "%a, %d %b %Y %H:%M:%S GMT").replace(
            tzinfo=timezone.utc
        )
    except (TypeError, ValueError):
        return None
    delta = (when - datetime.now(timezone.utc)).total_seconds()
    return max(0.0, delta)
