# Unified Accept-Header Resolver

**Priority:** High value, medium urgency
**Scope:** `src/amazon_ads_mcp/utils/http_client.py`, `src/amazon_ads_mcp/utils/media/` (new module), `src/amazon_ads_mcp/utils/export_content_type_resolver.py`
**Follows:** PR #68 (`fix(http): apply per-operation vendored media types to Accept header`)

## Context

PR #68 fixed the immediate 415 errors on Sponsored Products v3 entity CRUD (36 tools) and Target Promotion Groups v1 (4 tools) by extending the Accept-override guard in `AuthenticatedClient._inject_headers` to also fire when the existing Accept value is `*/*` or non-vendored. That fix is correct in scope, but it leaves three architectural smells in `_inject_headers`:

1. **Two parallel Accept-resolution blocks** at `http_client.py:520-557`. The media-registry block (lines 521-549) and the download/report heuristic block (lines 551-577) each duplicate the `*/*` discrimination and "prefer vendored" logic. After PR #68 both blocks check for `*/*` and both can write to `request.headers["Accept"]`.
2. **"First vendored from list" picker is hardcoded** at `http_client.py:528-531`: `next((a for a in accepts if a.startswith("application/vnd.")), accepts[0])`. When the OpenAPI operation declares multiple versioned vendored types (e.g. `v3`, `v4`, `v5`), the registry preserves spec ordering so the first listed wins. PR #68 explicitly flags this as the reason `sp_getRankedKeywordRecommendation` resolves to `v3+json` while Amazon's current request shape expects `v5+json`, producing a pre-existing 500 unrelated to the 415 fix.
3. **Policy buried in transport boolean logic.** PR #68's `should_override` is a four-clause boolean. There is no test for the "non-vendored existing → upgrade to vendored" path (the most controversial of the four). The decision lives implicitly in a single line of `_inject_headers` rather than in a documented resolver.

This roadmap item is the principled refactor that consolidates Accept resolution into one testable surface AND fixes the multi-version bug at the same time. PR #68's wire contract is preserved; only the internal shape changes.

## Motivating examples (from `dist/openapi/resources/SponsoredProducts.json`)

Operations that declare more than one versioned vendored content type today (extracted from the spec, not invented):

| Operation | Method + path | base | versions declared |
|---|---|---|---|
| `getRankedKeywordRecommendation` | `POST /sp/targets/keywords/recommendations` | `spkeywordsrecommendation` | 3, 4, 5 |
| `GetThemeBasedBidRecommendationForAdGroup_v1` | `POST /sp/targets/bid/recommendations` | `spthemebasedbidrecommendation` | 3, 4, 5 |
| `getTargetableCategories` | `GET /sp/targets/categories` | `spproducttargetingresponse` | 3, 4, 5 |
| `getCategoryRecommendationsForASINs` | `POST /sp/targets/categories/recommendations` | `spproducttargetingresponse` | 3, 4, 5 |
| `getRefinementsForCategory` | `GET /sp/targets/category/{categoryId}/refinements` | `spproducttargetingresponse` | 3, 4 |
| `CreateOptimizationRules`, `UpdateOptimizationRules`, `SearchOptimizationRules` | `/sp/rules/optimization*` | `spoptimizationrules` | 1, 2 |
| `CreateTargetPromotionGroups`, `ListTargetPromotionGroups` | `/sp/targetPromotionGroups[/list]` | `sptargetpromotiongroup` | 1, 2 |
| `CreateTargetPromotionGroupTargets`, `ListTargetPromotionGroupTargets` | `/sp/targetPromotionGroups/targets[/list]` | `sptargetpromotiongrouptarget` | 1, 2 |

For all of these, `MediaTypeRegistry.resolve(method, url)` returns an `accepts` list whose first vendored entry is whichever version the spec lists first. Today that is silently the lowest version, which is why `sp_getRankedKeywordRecommendation` 500s on Amazon's current shape. The TPG operations 200 today only because v1 and v2 happen to remain compatible — the same shape problem would bite the moment Amazon makes v2 the required version for a given request body.

## Goals

1. **Single source of truth for Accept resolution.** Replace the two blocks in `_inject_headers` with one call into a pure resolver.
2. **Prefer highest `vN+json` from spec-declared accepts** when multiple versions are present. Highest-major wins; on ties, highest-minor wins; on full ties, preserve spec order.
3. **Preserve PR #68's wire contract:**
   - Caller-pinned vendored Accept (e.g. tool explicitly sets `application/vnd.sptargetpromotiongroup.v2+json`) is never overridden.
   - Missing Accept, `*/*`, or non-vendored Accept gets upgraded to the highest spec-declared vendored type when one exists.
4. **Make the policy testable in isolation** as a pure function — no `httpx.AsyncClient` mock plumbing required for unit tests.
5. **Fold the download/report Accept heuristic into the same resolver** so there is one decision point. The download list is layered as a tie-breaker preference, not a separate writeback.

## Non-goals

- No change to `MediaTypeRegistry`'s storage shape (`_req_entries`, `_resp_entries` stay as lists of dicts).
- No change to `build_media_maps_from_spec` extraction logic — the resolver consumes what the registry already exposes.
- No change to download endpoint semantics — `resolve_download_accept_headers` keeps its current contract.
- No change to header-resolver (`HeaderNameResolver`) — it doesn't touch Accept.
- No `*.media.json` sidecar work (that's a separate dead-data issue PR #68's author flagged; track it elsewhere).

## Proposed shape

### New module: `utils/media/accept_resolver.py`

A pure-function resolver that owns the policy. No I/O, no httpx coupling.

```python
from typing import Iterable, Optional, Tuple
import re

# application/vnd.<base>.v<major>[.<minor>]+json
_VENDORED_RE = re.compile(
    r"^application/vnd\.([A-Za-z0-9]+)\.v(\d+)(?:\.(\d+))?\+json$"
)


def parse_vendored(ct: str) -> Optional[Tuple[str, int, int]]:
    """Return (base, major, minor) for application/vnd.<base>.v<N>[.<M>]+json,
    or None for any other content type. Minor defaults to 0."""
    m = _VENDORED_RE.match(ct or "")
    if not m:
        return None
    return m.group(1).lower(), int(m.group(2)), int(m.group(3) or 0)


def pick_highest_vendored(accepts: Iterable[str]) -> Optional[str]:
    """Pick the highest vN[.M]+json from an ordered list. Ties keep spec order."""
    best: Optional[Tuple[Tuple[int, int], int, str]] = None
    for idx, ct in enumerate(accepts or ()):
        parsed = parse_vendored(ct)
        if not parsed:
            continue
        _, major, minor = parsed
        # idx negated so earlier entries win on full version ties
        key = ((major, minor), -idx)
        if best is None or key > best[:2]:
            best = (key[0], key[1], ct)
    return best[2] if best else None


def resolve_accept(
    *,
    spec_accepts: Optional[list[str]],
    existing: Optional[str],
    download_overrides: Optional[list[str]] = None,
) -> Optional[str]:
    """Decide the Accept header value to set on a request.

    Returns the new value, or None to leave the request's Accept unchanged.

    Policy (in order):
      1. Caller-pinned vendored Accept (existing starts with "application/vnd.")
         is preserved — return None.
      2. If spec_accepts contains a vendored type, pick the highest vN+json.
         If existing is missing/"*/*"/non-vendored, return that.
      3. If spec_accepts has no vendored type but has any value, fall back to
         the first listed when existing is missing/"*/*".
      4. If download_overrides intersects spec_accepts, prefer that intersection.
         If no spec_accepts but existing is missing/"*/*", use overrides[0].
      5. Otherwise return None (leave existing alone).
    """
    existing_norm = (existing or "").strip()
    is_vendored_existing = existing_norm.startswith("application/vnd.")

    # Rule 1: caller-pinned vendored wins
    if is_vendored_existing:
        return None

    # Rule 4 (intersection branch): download overrides + spec accepts
    if download_overrides and spec_accepts:
        for ct in download_overrides:
            if ct in spec_accepts:
                if existing_norm in ("", "*/*") or not _is_vendored(existing_norm):
                    return ct

    # Rule 2: highest vendored from spec
    highest = pick_highest_vendored(spec_accepts or ())
    if highest and (
        existing_norm == "" or existing_norm == "*/*" or not _is_vendored(existing_norm)
    ):
        return highest

    # Rule 3: spec accepts present but no vendored entry
    if spec_accepts and (existing_norm == "" or existing_norm == "*/*"):
        return spec_accepts[0]

    # Rule 4 (download-only branch): no spec accepts to intersect against
    if download_overrides and (existing_norm == "" or existing_norm == "*/*"):
        return download_overrides[0]

    return None


def _is_vendored(ct: str) -> bool:
    return ct.startswith("application/vnd.")
```

### `_inject_headers` collapses to one call

```python
# 1) MEDIA NEGOTIATION
if self.media_registry:
    content_type, accepts = self.media_registry.resolve(method, url)
    if content_type and method.lower() != "get":
        request.headers["Content-Type"] = content_type
else:
    accepts = None

try:
    overrides = resolve_download_accept_headers(method, url) or None
except Exception as e:
    logger.debug("Download Accept resolver skipped: %s", e)
    overrides = None

new_accept = resolve_accept(
    spec_accepts=accepts,
    existing=request.headers.get("Accept"),
    download_overrides=overrides,
)
if new_accept:
    request.headers["Accept"] = new_accept
```

That replaces lines 520-577 of the post-PR-68 `_inject_headers` (~58 lines) with ~16 lines and zero policy logic.

## Version-selection algorithm details

`parse_vendored` and `pick_highest_vendored` need explicit edge-case behavior locked by tests:

- `application/vnd.spkeywordsrecommendation.v3+json` → `(spkeywordsrecommendation, 3, 0)`
- `application/vnd.measurementresult.v1.2+csv` → **not vendored JSON, returns None** (download resolver still handles CSV via `download_overrides`)
- `application/vnd.insightsbrandmetrics.v1.1+json` → `(insightsbrandmetrics, 1, 1)`
- Among `[v3+json, v4+json, v5+json]` → picks `v5+json`
- Among `[v1.0+json, v1.2+json, v1.1+json]` → picks `v1.2+json`
- Among `[v3+json, v3+json]` (duplicate listing) → picks first (spec order tie-break)
- Mixed bases (e.g. an operation that lists `spfoo.v1+json` and `spbar.v2+json` in one operation) → picks highest version regardless of base. **This is rare and worth a contract test;** if real specs do this we need to defer to spec ordering instead.

The tie-break choice (earlier index wins on full-tie) is intentional: when Amazon decides v3 is the right default and lists it first, we honor that.

## Test matrix

### Unit tests for `accept_resolver.py` (new file `tests/unit/test_accept_resolver.py`)

Pure-function tests, no httpx mocking. Each row is one assertion:

| Case | spec_accepts | existing | download_overrides | expected |
|---|---|---|---|---|
| Empty inputs | None | None | None | None |
| Missing Accept, single vendored | `["application/vnd.spCampaign.v3+json"]` | None | None | `vnd.spCampaign.v3+json` |
| `*/*` Accept, single vendored | `["application/vnd.spCampaign.v3+json"]` | `"*/*"` | None | `vnd.spCampaign.v3+json` |
| Non-vendored Accept, vendored available | `["application/vnd.spCampaign.v3+json"]` | `"application/json"` | None | `vnd.spCampaign.v3+json` |
| Caller-pinned vendored | `["application/vnd.tpg.v1+json", "application/vnd.tpg.v2+json"]` | `"application/vnd.tpg.v2+json"` | None | None |
| Caller-pinned vendored even when "wrong" | `["application/vnd.tpg.v2+json"]` | `"application/vnd.tpg.v1+json"` | None | None |
| Multi-version: highest wins | `[v3, v4, v5]` | `"*/*"` | None | `v5+json` |
| Multi-version: highest wins despite spec order | `[v5, v3, v4]` | `"*/*"` | None | `v5+json` |
| Major.minor: highest minor wins | `[v1.0, v1.2, v1.1]` | `"*/*"` | None | `v1.2+json` |
| Major beats minor | `[v1.99, v2.0]` | `"*/*"` | None | `v2.0+json` |
| Spec order tie-break on full version equality | `[v3+json, v3+json]` | `"*/*"` | None | first `v3+json` (id-stable) |
| No vendored in spec accepts, missing existing | `["application/json"]` | None | None | `"application/json"` |
| Download override intersects spec | `["application/vnd.adsexport.v1+json", "application/json"]` | None | `["application/vnd.adsexport.v1+json"]` | `vnd.adsexport.v1+json` |
| Download override doesn't intersect | `["application/vnd.spCampaign.v3+json"]` | `"*/*"` | `["text/csv"]` | `vnd.spCampaign.v3+json` (rule 2 wins) |
| Download override only, no spec | None | `"*/*"` | `["text/csv"]` | `"text/csv"` |
| Caller-pinned vendored + download override available | `["application/vnd.x.v1+json"]` | `"application/vnd.x.v1+json"` | `["application/json"]` | None (rule 1 absolute) |
| Empty string Accept (whitespace) treated as missing | `["application/vnd.x.v1+json"]` | `"   "` | None | `vnd.x.v1+json` |
| `*/*` with whitespace | `["application/vnd.x.v1+json"]` | `" */* "` | None | `vnd.x.v1+json` |
| Non-JSON vendored ignored by `pick_highest_vendored` | `["application/vnd.measurementresult.v1.2+csv"]` | `"*/*"` | None | None or first-listed (decide and lock) |

### PR #68 regression tests (preserved verbatim, must continue to pass)

- `tests/unit/test_client_accept_resolver.py::test_httpx_default_accept_is_overridden_with_vendored_type`
- `tests/unit/test_client_accept_resolver.py::test_explicit_vendored_accept_is_preserved`

These exercise the full `AuthenticatedClient.send` path with a mocked `MediaTypeRegistry`. They lock the wire contract PR #68 shipped. The refactor must not change their assertions. If we need to update the mocks because the resolver moved, that's fine — assertions stay identical.

### New integration test against real spec data

`tests/unit/test_accept_resolver_against_spec.py` — loads `dist/openapi/resources/SponsoredProducts.json`, builds a real `MediaTypeRegistry`, and asserts:

- `getRankedKeywordRecommendation` resolves to `application/vnd.spkeywordsrecommendation.v5+json` (the headline fix)
- `GetThemeBasedBidRecommendationForAdGroup_v1` resolves to `v5+json`
- `getTargetableCategories` resolves to `v5+json`
- `getCategoryRecommendationsForASINs` resolves to `v5+json`
- `getRefinementsForCategory` resolves to `v4+json`
- `CreateTargetPromotionGroups` resolves to `v2+json` (was v1 pre-refactor)
- All SP v3 entity CRUD operations resolve to `v3+json` (PR #68's contract — only one version declared, so highest is unchanged)

This test catches future regressions where:
- A new spec introduces a v6 and we need to confirm we pick it up automatically.
- Someone "fixes" the version logic in a way that breaks the spec contract.
- The spec extraction in `build_media_maps_from_spec` changes shape.

### Live-wire smoke (manual, not in CI)

Document a verification recipe in the PR body:

```bash
# Force resolved-version Accept on the headline endpoint
uv run python -c "
import asyncio
from amazon_ads_mcp.utils.media import MediaTypeRegistry
import json

reg = MediaTypeRegistry()
with open('dist/openapi/resources/SponsoredProducts.json') as f:
    reg.add_from_spec(json.load(f))

ct, accepts = reg.resolve('POST', 'https://advertising-api.amazon.com/sp/targets/keywords/recommendations')
print('content-type:', ct)
print('accepts:', accepts)
"
# Expected: accepts contains v3, v4, v5; resolve_accept picks v5
```

## Regression protection

Three layers:

1. **Pure-function unit tests** (table above) — fast, catches policy regressions in milliseconds.
2. **Spec-contract test** — catches drift between spec and resolver assumptions. Runs against committed `dist/openapi/resources/SponsoredProducts.json`; will need updating when the spec is regenerated.
3. **PR #68 wire contract tests** kept verbatim — catches any change to the `AuthenticatedClient` integration.

CI status: all three layers run under `uv run pytest` (default `-v` from pyproject.toml). The spec-contract test is fast (~50ms to load the spec) and can stay unmarked. No new `slow` markers needed.

## Rollout

This is a pure refactor of internal behavior with one intentional contract change (highest-version preference for multi-version operations). No env var gating needed.

1. Land the resolver module + unit tests in one commit.
2. Land the `_inject_headers` collapse + spec-contract test + PR #68 regression tests in a second commit.
3. Run full suite + linting.
4. PR description: link to this roadmap doc, list the operations whose resolved Accept changes (the multi-version table above), and call out `getRankedKeywordRecommendation` as the headline regression fix.
5. CHANGELOG entry under `Fixed`: "HTTP: prefer highest spec-declared `vN+json` for multi-version Amazon Ads operations (resolves pre-existing 500 on `sp_getRankedKeywordRecommendation` flagged in PR #68)."

No version bump triggered by this alone (it's a `fix:` per Conventional Commits, patch bump only when merged).

## Open questions to resolve during implementation

1. **Mixed-base accepts in one operation.** Does any current SponsoredProducts operation list two different `base` names in one accepts list? If yes, "highest version regardless of base" may be wrong; we'd need to bucket by base. Verify by extending the spec scan above.
2. **Non-JSON vendored types.** `application/vnd.measurementresult.v1.2+csv` is a real declared type. Should `pick_highest_vendored` consider non-JSON, or strictly JSON? Current proposal: JSON-only. The CSV case stays in `download_overrides`. Lock the behavior in the test row marked "decide and lock".
3. **`Content-Type` parity.** PR #68 only patched Accept. Do request bodies on multi-version operations also need a "highest vN+json" Content-Type? Current `MediaTypeRegistry.resolve` returns `req_map.get(...)` which is a single string, not a list, so the same picker doesn't apply directly. Worth a separate scan to confirm Content-Type is single-valued in every multi-version op; if not, expand the resolver.
4. **`HeaderNameResolver` interaction.** Confirmed not touched by Accept. No work needed.

## Out of scope (track separately)

- Dead `*.media.json` sidecar files in `dist/openapi/resources/` (PR #68 author flagged the shape mismatch with `MediaTypeRegistry.add_from_sidecar`). Open a separate cleanup issue.
- Cross-server error envelope contract work (separate roadmap, separate branch).
- Code Mode-side surfacing of the new resolver decisions (none needed; resolver runs at the transport layer below code mode).
