# Unified Accept-Header Resolver

**Priority:** High value, medium urgency
**Scope:** `src/amazon_ads_mcp/utils/http_client.py`, `src/amazon_ads_mcp/utils/media/` (new module), `src/amazon_ads_mcp/utils/export_content_type_resolver.py`
**Follows:** PR #68 (`fix(http): apply per-operation vendored media types to Accept header`)

## Context

PR #68 fixed the immediate 415 errors on Sponsored Products v3 entity CRUD (36 tools) and Target Promotion Groups v1 (4 tools) by extending the Accept-override guard in `AuthenticatedClient._inject_headers` to also fire when the existing Accept value is `*/*` or non-vendored. That fix is correct in scope, but it leaves three architectural smells in `_inject_headers`:

1. **Two parallel Accept-resolution blocks** at `http_client.py:520-557`. The media-registry block (lines 521-549) and the download/report heuristic block (lines 551-577) each duplicate the `*/*` discrimination and "prefer vendored" logic. After PR #68 both blocks check for `*/*` and both can write to `request.headers["Accept"]`.
2. **"First vendored from list" picker is hardcoded** at `http_client.py:528-531`: `next((a for a in accepts if a.startswith("application/vnd.")), accepts[0])`. When the OpenAPI operation declares multiple versioned vendored types (e.g. `v3`, `v4`, `v5`), the registry returns them lexically sorted (single-digit versions sort numerically by coincidence), so the first vendored entry is `v3+json`. PR #68 explicitly flags this as the reason `sp_getRankedKeywordRecommendation` resolves to `v3+json` while Amazon's current request shape expects `v5+json`, producing a pre-existing 500 unrelated to the 415 fix.
3. **Policy buried in transport boolean logic.** PR #68's `should_override` is a four-clause boolean. There is no test for the "non-vendored existing → upgrade to vendored" path (the most controversial of the four). The decision lives implicitly in a single line of `_inject_headers` rather than in a documented resolver.

This roadmap item is the principled refactor that consolidates Accept resolution into one testable surface AND fixes the multi-version bug at the same time. PR #68's wire contract is preserved; only the internal shape changes.

## Design discipline

**Spec-driven, not hand-curated.** New helpers must justify why the OpenAPI spec can't drive the behavior.

- **Build-time decomposition of spec data is spec-driven.** Splitting one spec into `<ns>.json` (paths/schemas), `<ns>.media.json` (per-op content types), `<ns>.manifest.json`, and `<ns>.transform.json` (genuinely spec-orphaned overrides) is not a wrapper — it's the same spec data, partitioned for context efficiency. Generators read the canonical spec; loaders consume the partitions.
- **Hand-curated per-operation overrides are not spec-driven.** A `transform.json.accept_override` field that names specific operationIds and pins specific versions would create maintenance debt and break silently when Amazon renames operations or ships new versions. Rejected.
- **The runtime resolver picks "highest declared version"** as a spec-driven heuristic. If a tool genuinely needs a specific version, it pins Accept at the call site (preserved by PR #68's caller-pinned contract) — the requirement lives where it's known, not in a side file where it goes stale.
- **`transform.json` carries only what the spec genuinely cannot express** — pagination param names, batch behavior, output projections, arg_aliases for fields that resist clean OpenAPI representation. Accept resolution does NOT belong there because the spec already declares which versions exist.

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

For all of these, `MediaTypeRegistry.resolve(method, url)` returns an `accepts` list — deduplicated and lexically sorted (see Registry contract below). The current picker takes the first vendored entry, which after lexical sort happens to be the lowest single-digit version (`v3` < `v4` < `v5`). That's why `sp_getRankedKeywordRecommendation` 500s on Amazon's current shape. The TPG operations 200 today only because v1 and v2 happen to remain compatible — the same shape problem would bite the moment Amazon makes v2 the required version for a given request body.

## Registry contract

`MediaTypeRegistry.resolve(method, url)` returns `accepts` as a deduplicated, lexically sorted list (see `utils/media/types.py:204-212` — `accepts: Set[str] = set()` then `resp_media[…] = sorted(accepts)`). The resolver MUST NOT depend on input order. All version comparisons happen on parsed `(major, minor)` ints. Lexical sort is correct for single-digit versions but not for two-digit (`v10` lexically precedes `v9`); the parsed-int picker is order-independent and handles both.

## Goals

1. **Single source of truth for Accept resolution.** Replace the two blocks in `_inject_headers` with one call into a pure resolver.
2. **Prefer highest `vN[.M]+json` from spec-declared accepts** when multiple versions are present. Highest-major wins; on ties, highest-minor wins; full version duplicates are deduped by the registry upstream and never reach the picker.
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
- No `*.media.json` sidecar work in PR 1 (resolver). Sidecar restoration is Phase 2 (separate PR after PR 1 lands) — see "Phase 2: Media sidecar restoration" below.

## Proposed shape

### New module: `utils/media/accept_resolver.py`

A pure-function resolver that owns the policy. No I/O, no httpx coupling.

```python
from typing import Iterable, Optional, Tuple
import re

# application/vnd.<base>.v<major>[.<minor>]+json
# Base allows alphanumerics, dots, hyphens, underscores — real specs use
# compound bases like "spproductrecommendationresponse.asins" and
# "SponsoredBrands.SponsoredBrandsMigrationApi".
_VENDORED_JSON_RE = re.compile(
    r"^application/vnd\.([A-Za-z0-9._-]+)\.v(\d+)(?:\.(\d+))?\+json$"
)


def parse_vendored_json(ct: str) -> Optional[Tuple[str, int, int]]:
    """Return (base, major, minor) for application/vnd.<base>.v<N>[.<M>]+json,
    or None for any other content type (including text/vnd.*+csv variants
    and bare application/vnd.<base>.v<N> with no +json suffix). Minor
    defaults to 0. Base is lowercased for stable comparison."""
    m = _VENDORED_JSON_RE.match(ct or "")
    if not m:
        return None
    return m.group(1).lower(), int(m.group(2)), int(m.group(3) or 0)


def pick_highest_vendored_json(accepts: Iterable[str]) -> Optional[str]:
    """Pick the highest vN[.M]+json from a list of content types.

    When the list contains multiple distinct bases (rare but real — e.g. an
    op declaring both spproductrecommendationresponse.asins and
    spproductrecommendationresponse.themes), the picker abstains and returns
    None. The caller cannot decide between bases without semantic context;
    rule 4 of resolve_accept handles this by falling back to first-listed.

    When only one base is present, return the highest (major, minor)."""
    parsed = [(parse_vendored_json(ct), ct) for ct in (accepts or ())]
    parsed = [(p, ct) for (p, ct) in parsed if p is not None]
    if not parsed:
        return None
    bases = {p[0] for (p, _) in parsed}
    if len(bases) > 1:
        return None  # mixed bases — abstain, let caller fall back
    best = max(parsed, key=lambda item: (item[0][1], item[0][2]))
    return best[1]


def resolve_accept(
    *,
    spec_accepts: Optional[list[str]],
    existing: Optional[str],
    download_overrides: Optional[list[str]] = None,
) -> Optional[str]:
    """Decide the Accept header value to set on a request.

    Returns the new value, or None to leave the request's Accept unchanged.

    Policy (in execution order — code below mirrors this exactly):
      1. Caller-pinned vendored Accept (existing starts with "application/vnd.")
         is preserved unconditionally — return None.
      2. If download_overrides ∩ spec_accepts is non-empty AND existing is
         missing / "*/*" / non-vendored — return the first overlapping value.
         (Download endpoints declare a specific vendored type; that wins
         over "highest vendored" because the download contract is more
         specific than spec-listed alternatives.)
      3. If spec_accepts contains vendored JSON of a single base, pick the
         highest vN[.M]+json. Override existing when missing / "*/*" /
         non-vendored.
      4. If spec_accepts contains values but no single-base vendored JSON
         (mixed bases, no JSON variants, or non-JSON vendored) — fall back
         to first-listed when existing is missing / "*/*". Don't touch a
         non-vendored caller value.
      5. If only download_overrides exists (no spec_accepts) — return
         overrides[0] when existing is missing / "*/*".
      6. Otherwise return None (leave existing alone)."""
    existing_norm = (existing or "").strip()
    is_vendored_existing = existing_norm.startswith("application/vnd.")

    # Rule 1: caller-pinned vendored wins
    if is_vendored_existing:
        return None

    # Rule 2: download_overrides ∩ spec_accepts (intersection wins over highest)
    if download_overrides and spec_accepts:
        for ct in download_overrides:
            if ct in spec_accepts:
                if existing_norm in ("", "*/*") or not _is_vendored(existing_norm):
                    return ct

    # Rule 3: highest vendored JSON from spec (single base)
    highest = pick_highest_vendored_json(spec_accepts or ())
    if highest and (
        existing_norm == "" or existing_norm == "*/*" or not _is_vendored(existing_norm)
    ):
        return highest

    # Rule 4: spec accepts present but no single-base vendored JSON
    if spec_accepts and (existing_norm == "" or existing_norm == "*/*"):
        return spec_accepts[0]

    # Rule 5: download-only (no spec accepts)
    if download_overrides and (existing_norm == "" or existing_norm == "*/*"):
        return download_overrides[0]

    # Rule 6: leave alone
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

`parse_vendored_json` and `pick_highest_vendored_json` need explicit edge-case behavior locked by tests. All examples below are verified against current `dist/openapi/resources/`:

**Parser behavior:**

- `application/vnd.spkeywordsrecommendation.v3+json` → `(spkeywordsrecommendation, 3, 0)`
- `application/vnd.spproductrecommendationresponse.asins.v3+json` → `(spproductrecommendationresponse.asins, 3, 0)` (dotted base, real type from SP spec)
- `application/vnd.SponsoredBrands.SponsoredBrandsMigrationApi.v4+json` → `(sponsoredbrands.sponsoredbrandsmigrationapi, 4, 0)` (compound base, real type)
- `text/vnd.measurementresult.v1.2+csv` → `None` (non-JSON, opaque to picker — download resolver still handles via `download_overrides`)
- `application/vnd.GlobalRegistrationService.TermsTokenResource.v1` → `None` (no `+json` suffix — real type from a spec, intentionally rejected by the parser)
- `application/vnd.insightsbrandmetrics.v1.1+json` → `(insightsbrandmetrics, 1, 1)`

**Picker behavior:**

- Among `[v3+json, v4+json, v5+json]` (single base) → picks `v5+json`
- Among `[v1.0+json, v1.2+json, v1.1+json]` → picks `v1.2+json`
- Among `[v1.99+json, v2.0+json]` → picks `v2.0+json` (major beats minor)
- Multiple bases in one accepts list (e.g. `spproductrecommendationresponse.asins` + `…themes`) → picker abstains, returns `None`. `resolve_accept` rule 4 falls back to first-listed.

Full version duplicates cannot reach the picker — `MediaTypeRegistry.add_from_spec` collapses via `set()` upstream (see Registry contract above). No tie-break logic is needed in the picker.

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
| Multi-version: highest wins regardless of input order | `[v5, v3, v4]` | `"*/*"` | None | `v5+json` (picker is order-independent on parsed `(major, minor)`) |
| Major.minor: highest minor wins | `[v1.0, v1.2, v1.1]` | `"*/*"` | None | `v1.2+json` |
| Major beats minor | `[v1.99, v2.0]` | `"*/*"` | None | `v2.0+json` |
| Dotted base parses correctly | `["application/vnd.spproductrecommendationresponse.asins.v3+json"]` | None | None | `vnd.spproductrecommendationresponse.asins.v3+json` |
| Compound base with hyphen-like punctuation parses | `["application/vnd.SponsoredBrands.SponsoredBrandsMigrationApi.v4+json"]` | None | None | `vnd.SponsoredBrands.SponsoredBrandsMigrationApi.v4+json` |
| Mixed dotted bases (single op declares two) | `["application/vnd.x.asins.v3+json", "application/vnd.x.themes.v3+json"]` | `"*/*"` | None | `vnd.x.asins.v3+json` (picker abstains, rule 4 first-listed; lexical sort already places `asins` before `themes`) |
| Mixed bases with version difference | `["application/vnd.bar.v5+json", "application/vnd.foo.v3+json"]` | `"*/*"` | None | `vnd.bar.v5+json` (picker abstains; rule 4 first-listed after registry's lexical sort places `bar` before `foo`) |
| No vendored in spec accepts, missing existing | `["application/json"]` | None | None | `"application/json"` |
| Download override intersects spec | `["application/vnd.adsexport.v1+json", "application/json"]` | None | `["application/vnd.adsexport.v1+json"]` | `vnd.adsexport.v1+json` (rule 2 intersection) |
| Download override doesn't intersect | `["application/vnd.spCampaign.v3+json"]` | `"*/*"` | `["text/csv"]` | `vnd.spCampaign.v3+json` (rule 3 wins) |
| Download override only, no spec | None | `"*/*"` | `["text/csv"]` | `"text/csv"` (rule 5) |
| Caller-pinned vendored + download override available | `["application/vnd.x.v1+json"]` | `"application/vnd.x.v1+json"` | `["application/json"]` | None (rule 1 absolute) |
| Empty string Accept (whitespace) treated as missing | `["application/vnd.x.v1+json"]` | `"   "` | None | `vnd.x.v1+json` |
| `*/*` with whitespace | `["application/vnd.x.v1+json"]` | `" */* "` | None | `vnd.x.v1+json` |
| Non-JSON vendored only, generic existing | `["text/vnd.measurementresult.v1.2+csv"]` | `"*/*"` | None | `"text/vnd.measurementresult.v1.2+csv"` (picker returns None, rule 4 first-listed; resolver stays neutral on non-JSON semantics) |

### PR #68 regression tests (preserved verbatim, must continue to pass)

- `tests/unit/test_client_accept_resolver.py::test_httpx_default_accept_is_overridden_with_vendored_type`
- `tests/unit/test_client_accept_resolver.py::test_explicit_vendored_accept_is_preserved`

These exercise the full `AuthenticatedClient.send` path with a mocked `MediaTypeRegistry`. They lock the wire contract PR #68 shipped. The refactor must not change their assertions. If we need to update the mocks because the resolver moved, that's fine — assertions stay identical.

### Source-agnosticism guarantee (PR 1 acceptance criterion)

The resolver must make zero assumptions about how the registry was populated. All pure-function unit tests inject `accepts` directly as a list of strings; no test depends on whether the data came from `MediaTypeRegistry.add_from_spec(spec)` or `MediaTypeRegistry.add_from_sidecar(sidecar)`. This guarantee is what makes Phase 1 (resolver) and Phase 2 (sidecar restoration) independent — the resolver works against either data source, and Phase 2 can land later without resolver changes.

Test setup convention: pass `spec_accepts` as an explicit list literal in every unit test. Do NOT instantiate `MediaTypeRegistry` in resolver unit tests. The integration test below is the only place where the resolver runs against a real registry, and that test is allowed to source data from `add_from_spec` (today) or `add_from_sidecar` (post-Phase 2) — the assertions are the same either way.

### Spec-contract integration tests against real spec data

`tests/unit/test_accept_resolver_against_spec.py` — loads multiple specs from `dist/openapi/resources/`, builds real `MediaTypeRegistry` instances, and asserts the resolver's behavior across the full surface that the resolver actually affects:

**SponsoredProducts.json (12 multi-version + PR #68 contract):**
- `getRankedKeywordRecommendation` → `application/vnd.spkeywordsrecommendation.v5+json` (the headline fix)
- `GetThemeBasedBidRecommendationForAdGroup_v1` → `v5+json`
- `getTargetableCategories` → `v5+json`
- `getCategoryRecommendationsForASINs` → `v5+json`
- `getRefinementsForCategory` → `v4+json`
- `CreateOptimizationRules` / `UpdateOptimizationRules` / `SearchOptimizationRules` → `v2+json`
- `CreateTargetPromotionGroups` / `ListTargetPromotionGroups` / `CreateTargetPromotionGroupTargets` / `ListTargetPromotionGroupTargets` → `v2+json`
- PR #68 contract: SP v3 entity CRUD ops (campaigns, adGroups, keywords, productAds, etc.) → `v3+json`

**AmazonDSPConversions.json (2 multi-version + 1 mixed-base):**
- `dspAmazonListConversionDefinitions` → `vnd.dspconversiondefinition.v2+json`
- `dspAmazonGetAssociatedConversionDefinitionsForOrder` → `vnd.dsporderconversionassociation.v2+json`
- `dspAmazonGetAssociatedMobileAppForConversionDefinition` (mixed-base) → first-listed via rule 4 abstention

**AmazonDSPMeasurement.json (20 multi-version single-base ops):**
- All 20 ops across measurement eligibility, study management, study results, surveys, vendor products
- Bases: `measurementeligibility` (v1.1, v1.3), `studymanagement` (up to v1.3), `measurementresult`, `measurementvendor`, `ocmbrands`
- Test rows derived from a one-shot spec walk; concrete strings committed verbatim. After spec regen, re-walk the spec by hand and update any rows whose highest-version expectation has shifted.

**BrandMetrics.json (2 mixed-base ops, current contract):**
- Both ops declare `insightsbrandmetrics.v1+json`, `insightsbrandmetrics.v1.1+json`, AND `insightsbrandmetricserror.v1+json`
- Picker abstains on mixed bases → resolver returns lexical-first (`insightsbrandmetrics.v1+json`)
- Documented contract: callers needing v1.1 specifically must pin Accept at the call site (preserved by resolver rule 1). Bucket-by-base or special-casing "error" base names rejected per design discipline.

**ReportingVersion3.json (0 multi-version, sanity scan):**
- One parameterized assertion walks every op; resolver must return a value present in declared accepts. Avoids per-op identity-coverage bloat for single-version specs.

**Generalized spec-walk crash test:**
- Parametrized across `sp_spec`, `dsp_conversions_spec`, `dsp_measurement_spec`, `brandmetrics_spec`, `reporting_v3_spec`
- For each operation in each spec, asserts the resolver returns `str | None` (never crashes) for `existing` ∈ {None, "*/*", "application/json"}
- This is the future-proofing test that catches Amazon shipping new multi-base shapes in any service.

**Wire-path regression test** (`tests/integration/test_authenticated_client_dsp_wire.py`):
- Real `AuthenticatedClient`, real `MediaTypeRegistry` from `AmazonDSPConversions.json`, fully mocked auth (no env credentials)
- Intercepts `httpx.AsyncClient.send`, asserts the wire `Accept` value is `vnd.dspconversiondefinition.v2+json`
- Plus a caller-pinned-vendored test that confirms rule 1 holds on the wire
- Provides CI regression protection on a DSP endpoint, not just SP

This test layer catches:
- A new spec version introducing a v6 — picker auto-upgrades; spec-contract test surfaces the change loudly
- Someone "fixing" the version logic in a way that breaks the spec contract
- Spec extraction in `build_media_maps_from_spec` changing shape (e.g. dropping the lexical sort)
- Amazon shipping a multi-base accepts list in any service — generalized crash walk catches it
- A regression in `_inject_headers` no longer calling the resolver — wire-path test catches it

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

## Open questions

**Resolved at plan time:**

1. **Mixed-base accepts in one operation.** ✓ **Resolved.** Real and rare: SP spec declares both `spproductrecommendationresponse.asins` and `…themes` on the same operation. Locked behavior: `pick_highest_vendored_json` abstains (returns `None`) when more than one distinct base is present; `resolve_accept` rule 4 falls back to first-listed (after the registry's lexical sort). The implementer should NOT bucket by base and pick "highest per base" — that would require semantic context the resolver doesn't have. The `text/vnd.…+csv` case is also handled by abstention (parser returns None for non-JSON, picker returns None for empty parsed list, rule 4 returns first-listed).
2. **Non-JSON vendored types.** ✓ **Resolved.** Picker is JSON-only by design (`_VENDORED_JSON_RE` requires `+json` suffix). Non-JSON vendored types (CSV via `text/vnd.…+csv`, bare-version variants without `+json`) are opaque to the picker and surface via rule 4's first-listed fallback. The `download_overrides` path remains the right place for endpoints that need explicit non-JSON Accept negotiation.
3. **`HeaderNameResolver` interaction.** ✓ **Resolved.** `HeaderNameResolver` (`src/amazon_ads_mcp/utils/header_resolver.py`) only handles client/scope/account header NAMES. Does not touch Accept. No work needed.

**Still open — implementer TODO before writing code:**

4. **`Content-Type` parity.** PR #68 only patched Accept. `MediaTypeRegistry.resolve` returns `content_type` as a single string (already-picked first via `sorted(rb_content.keys())[0]` at `utils/media/types.py:201`), not a list. Re-scan `dist/openapi/resources/` for any operation whose `requestBody.content` declares more than one vendored content type. If any exist with multi-version, expand the resolver to cover Content-Type with the same algorithm and add a Content-Type write inside `resolve_accept` (or a sibling). Likely none exist — most Amazon Ads operations request a single Content-Type even when they offer multiple response media types — but verify before locking the implementation.

## Phase 2: Media sidecar restoration (separate PR, after PR 1 lands)

The `*.media.json` sidecars exist as part of the build-time decomposition strategy that splits each spec into smaller artifacts for context efficiency. Today the strategy is half-implemented: the generator emits the wrong shape (`{namespace, content_types: [flat union]}`) and the loader calls `add_from_spec(media_spec)` instead of `add_from_sidecar(media_spec)`, so the sidecar contributes zero data and routing only works because `add_from_spec(spec)` is called separately on the unslimmed spec. The moment slimming strips response content from the spec, routing breaks.

This is a fix-in-place, not a deletion. Sidecar restoration is fully spec-driven (the sidecar is build-time generated from the canonical spec, just decomposed) and is the precondition for future aggressive spec slimming.

**PR 2 acceptance criteria:**

1. **Generator** (`.build/scripts/process_openapi_specs.py:generate_media_sidecar`) rewritten to emit per-operation shape matching the contract `MediaTypeRegistry.add_from_sidecar()` already accepts:
   ```json
   {
     "version": "1.0",
     "namespace": "SponsoredProducts",
     "requests": {"POST /sp/campaigns/list": "application/vnd.spCampaign.v3+json", ...},
     "responses": {"POST /sp/campaigns/list": ["application/vnd.spCampaign.v3+json", ...], ...}
   }
   ```
2. **Loader** (`server_builder.py:638`) switches from `add_from_spec(media_spec)` to `add_from_sidecar(media_spec)`. The redundant `add_from_spec(spec)` call directly above can be left in place during PR 2 (both paths populate the registry); evaluate removal in a follow-up only when slimming is actually enabled.
3. **Parity test suite (the drift guardrail).** For each spec in `dist/openapi/resources/`, build two registries — one populated from the spec only via `add_from_spec(spec)`, one populated from the sidecar only via `add_from_sidecar(media_spec)` — and assert `resolve(method, url)` returns identical `(content_type, accepts)` for every operation in the spec. Catches: generator drift, loader bugs, regression in either pipeline. This is the single test that prevents the two halves from drifting again.
4. **No new sidecar consumers.** Phase 2 fixes the existing consumer; it does not add new ones. If a future spec-slimming PR strips response content from runtime specs, the existing sidecar consumer continues to work because its data is already populated at startup.

**(b)-fallback condition.** If aggressive slimming (e.g. `SLIM_OPENAPI_AGGRESSIVE=true` or `SLIM_OPENAPI_STRIP_RESPONSES=true` becoming default) is about to be enabled in the same release window as PR 1, flip the order: ship sidecar restoration first so the resolver lands on a clean data layer. As of this writing the slimming env vars are off by default (per CLAUDE.md), so order (a) — resolver first, sidecar second — is the faster and still safe path.

## Out of scope (track separately)

- Cross-server error envelope contract work (separate roadmap, separate branch).
- Code Mode-side surfacing of the new resolver decisions (none needed; resolver runs at the transport layer below code mode).
- Aggressive spec slimming follow-up. Once Phase 2 lands and parity tests are green, a separate PR can strip response content from runtime specs to claim the context-bloat win that motivated the sidecar split in the first place. Track as its own roadmap item.
