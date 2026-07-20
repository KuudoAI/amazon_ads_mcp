"""Low-cardinality path normalizer for the metered transport (Task 22
ruling #7).

Passed to ``MeteringRuntime.wrap_transport(..., path_normalizer=...)``
(see ``metering/adapter.py``). Never touched on a Python version where
metering is unavailable (:mod:`amazon_ads_mcp.metering.compat`) -- this
module has no dependency on ``mcp_outbound_metering`` itself, only on
``httpx`` (already a core dependency of this project), so it stays
importable on every supported Python version.
"""

from __future__ import annotations

import re

import httpx

__all__ = ["normalize_path"]

# A path segment made up entirely of digits, e.g. the "42" in
# "/v2/campaigns/42".
_NUMERIC_SEGMENT_RE = re.compile(r"^\d+$")

# Amazon Ads entity-id shape: a leading "A" followed by 8+ uppercase
# letters/digits, e.g. profile/entity ids like "ENTITY1AZ2BCD3EF".
_AMAZON_ENTITY_ID_RE = re.compile(r"^A[A-Z0-9]{8,}$")

# Canonical UUID (with dashes), case-insensitive.
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def _is_high_cardinality(segment: str) -> bool:
    """True for a path segment that should collapse to ``{id}`` -- pure
    digits, an Amazon entity-id shape, or a UUID. Stable segments (e.g.
    ``v2``, ``profiles``, ``campaigns``) never match any of these and pass
    through unchanged, per design (``/v2/profiles`` stays itself)."""
    if not segment:
        return False
    return bool(
        _NUMERIC_SEGMENT_RE.match(segment)
        or _AMAZON_ENTITY_ID_RE.match(segment)
        or _UUID_RE.match(segment)
    )


def normalize_path(request: httpx.Request) -> str:
    """Collapse high-cardinality path segments (numeric ids, Amazon
    entity-id shapes, UUIDs) to ``{id}`` so per-record identifiers never
    become distinct, high-cardinality ``url.path`` dimension values.
    Operates on ``request.url.path`` only -- httpx never includes the
    query string there, so this normalizer can never leak one (design
    ruling #7)."""
    segments = request.url.path.split("/")
    normalized = ["{id}" if _is_high_cardinality(segment) else segment for segment in segments]
    return "/".join(normalized)
