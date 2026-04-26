"""Pure-function Accept-header resolver.

Owns the policy for choosing an HTTP ``Accept`` value at request time. Decoupled
from ``httpx`` and from :class:`MediaTypeRegistry` so the policy can be unit
tested in isolation. ``AuthenticatedClient._inject_headers`` is the only
production caller; tests inject ``spec_accepts`` directly.

Design discipline (see ``docs/roadmap/unified-accept-resolver.md``):

* Spec-driven, not hand-curated. The picker prefers the highest spec-declared
  ``vN[.M]+json``. There is no per-operation override mechanism — tools that
  need a specific version pin Accept at the call site (preserved by the
  caller-pinned rule below).
* The CSV / non-JSON variants live behind ``download_overrides`` and are
  treated as opaque first-listed by this resolver — non-JSON semantics are
  the download path's concern.
"""

from __future__ import annotations

import re
from typing import Iterable, List, Optional, Tuple

# application/vnd.<base>.v<major>[.<minor>]+json
#
# Base allows alphanumerics, dots, hyphens, underscores. Real specs use
# compound bases such as ``spproductrecommendationresponse.asins`` and
# ``SponsoredBrands.SponsoredBrandsMigrationApi``; narrower regexes drop
# valid types silently and produce 415 / 500 against Amazon.
_VENDORED_JSON_RE = re.compile(
    r"^application/vnd\.([A-Za-z0-9._-]+)\.v(\d+)(?:\.(\d+))?\+json$"
)


def parse_vendored_json(ct: Optional[str]) -> Optional[Tuple[str, int, int]]:
    """Parse a vendored JSON content type into ``(base, major, minor)``.

    Returns ``None`` for any content type that is not
    ``application/vnd.<base>.v<N>[.<M>]+json``. Notably ``None`` for
    ``text/vnd.*+csv`` variants and for bare ``application/vnd.<base>.v<N>``
    types with no ``+json`` suffix — those are out of scope for the picker
    and surface via the first-listed fallback. ``minor`` defaults to 0.
    Base is lowercased for stable comparison.
    """
    if not ct:
        return None
    m = _VENDORED_JSON_RE.match(ct)
    if not m:
        return None
    return m.group(1).lower(), int(m.group(2)), int(m.group(3) or 0)


def pick_highest_vendored_json(accepts: Optional[Iterable[str]]) -> Optional[str]:
    """Pick the highest ``vN[.M]+json`` from a list of content types.

    Returns ``None`` when:

    * the input is empty or contains no vendored JSON types, or
    * the input contains multiple distinct *bases* (e.g. an operation
      declaring both ``spproductrecommendationresponse.asins`` and
      ``…themes``). The picker abstains because version comparison cannot
      decide between two semantic shapes; the caller is expected to fall
      back to first-listed.

    When a single base is present, returns the original content-type string
    of the highest ``(major, minor)``.
    """
    if not accepts:
        return None
    parsed: List[Tuple[Tuple[str, int, int], str]] = []
    for ct in accepts:
        p = parse_vendored_json(ct)
        if p is not None:
            parsed.append((p, ct))
    if not parsed:
        return None
    bases = {p[0] for (p, _) in parsed}
    if len(bases) > 1:
        return None  # mixed bases — abstain, let caller fall back
    best = max(parsed, key=lambda item: (item[0][1], item[0][2]))
    return best[1]


def _is_vendored(ct: str) -> bool:
    return ct.startswith("application/vnd.")


def resolve_accept(
    *,
    spec_accepts: Optional[List[str]],
    existing: Optional[str],
    download_overrides: Optional[List[str]] = None,
) -> Optional[str]:
    """Decide the ``Accept`` header value to set on an outbound request.

    Returns the new ``Accept`` value, or ``None`` to leave the request's
    ``Accept`` unchanged.

    Policy (executed in this order — code below mirrors the docstring exactly):

    1. **Caller-pinned vendored Accept is preserved unconditionally.**
       If ``existing`` starts with ``application/vnd.``, return ``None``
       (do not modify). Tools that pin a specific version know what they need.
    2. **Vendored intersection of download_overrides and spec_accepts.**
       If any *vendored* value (``application/vnd.*`` or ``text/vnd.*``)
       appears in both ``download_overrides`` and ``spec_accepts`` AND
       ``existing`` is missing / ``"*/*"`` / non-vendored, return that
       overlapping value. Non-vendored intersections (e.g. both sides
       agreeing on ``application/json``) do NOT count — those are generic
       fallbacks, not specific download contracts.
    3. **Highest single-base vendored JSON from spec.**
       If ``spec_accepts`` contains vendored JSON of a single base, pick the
       highest ``vN[.M]+json``. Override ``existing`` only when missing /
       ``"*/*"`` / non-vendored.
    4. **First vendored from spec (any subtype).**
       If ``spec_accepts`` has any ``application/vnd.*`` value but the
       version picker abstained (mixed bases, non-version vendored types
       like ``application/vnd.openxmlformats-…sheet``, etc.), return the
       first vendored entry. Preserves "vendored beats generic" intent
       even when version selection isn't applicable.
    5. **First-listed spec value.**
       When spec has values but nothing vendored, return the first-listed
       only if ``existing`` is missing / ``"*/*"``. Don't touch a caller-set
       non-vendored value.
    6. **Download-only fallback.**
       If only ``download_overrides`` exists (no ``spec_accepts``), return
       ``download_overrides[0]`` when ``existing`` is missing / ``"*/*"``.
    7. **Otherwise return None** (leave existing unchanged).
    """
    existing_norm = (existing or "").strip()
    is_vendored_existing = existing_norm.startswith("application/vnd.")

    # Rule 1: caller-pinned vendored wins
    if is_vendored_existing:
        return None

    is_generic_existing = existing_norm in ("", "*/*")
    is_overrideable = is_generic_existing or not _is_vendored(existing_norm)

    # Rule 2: vendored ∩ of download_overrides and spec_accepts
    if download_overrides and spec_accepts and is_overrideable:
        spec_set = set(spec_accepts)
        for ct in download_overrides:
            if ct in spec_set and (
                ct.startswith("application/vnd.") or ct.startswith("text/vnd.")
            ):
                return ct

    # Rule 3: highest vendored JSON from spec (single base)
    highest = pick_highest_vendored_json(spec_accepts)
    if highest and is_overrideable:
        return highest

    # Distinguish WHY the picker abstained: if any +json vendored type exists,
    # abstention means mixed bases (we can't decide between asins/themes-style
    # shapes by version comparison). When that's the case, do NOT silently
    # pick a vendored value via rule 4 — fall to first-listed so application/json
    # surfaces the ambiguity to the caller. Rule 4 is reserved for the case
    # where there's no vendored JSON to compare in the first place
    # (e.g. xlsx mime, csv, brand-specific binaries).
    has_vendored_json = bool(spec_accepts) and any(
        parse_vendored_json(ct) is not None for ct in spec_accepts
    )

    # Rule 4: first vendored from spec (any subtype) when picker had nothing
    # to compare. Preserves "vendored over generic" intent for non-version
    # vendored types like application/vnd.openxmlformats-…sheet.
    if spec_accepts and is_overrideable and not has_vendored_json:
        first_vendored = next(
            (ct for ct in spec_accepts if _is_vendored(ct)),
            None,
        )
        if first_vendored:
            return first_vendored

    # Rule 5: spec has values, fall back to first-listed
    if spec_accepts and is_generic_existing:
        return spec_accepts[0]

    # Rule 6: download-only (no spec accepts)
    if download_overrides and is_generic_existing:
        return download_overrides[0]

    # Rule 7: leave alone
    return None


__all__ = [
    "parse_vendored_json",
    "pick_highest_vendored_json",
    "resolve_accept",
]
