# Revised Plan: Integrate Ads API v1 Field Catalogs into `list_report_fields`

**Status:** Ready for implementation — locked after review
**Closes:** Issue 4 (v1 field-discovery failure loop)
**Scope:** Additive tool + packaged metadata; no breaking changes.

---

## 1. Context

`list_report_fields` currently returns a curated minimal v1 baseline (~10 fields, `status: "empirically-validated-minimal"`). Ads API v1 OpenAPI does **not** enumerate `query.fields`, so LLMs guess — producing the documented 4-attempt failure loop.

Extracted catalogs in `.build/adsv1_specs/`:
- `amazon_ads_v1_dimensions.json` — 118 entries, 76 KB
- `amazon_ads_v1_metrics.json` — 700 entries, 1.3 MB

Each entry carries `field_id`, `display_name`, `data_type`, `description`, `required_fields`, `complementary_fields`, `compatible_dimensions`, `incompatible_dimensions`, `v3_name_dsp`, `v3_name_sponsored_ads`, and `source.{md_file, parsed_at}`.

Full catalog exceeds `MAX_MCP_OUTPUT_TOKENS=25000`. Solution: one bounded, opt-in tool that surfaces the **compatibility graph** as the primary value, with provenance on every field.

## 2. Goals

- Close the v1 field-discoverability gap that produced the original failure loop.
- Preserve the existing no-arg `list_report_fields` response (schema-compatible, equal field values).
- Make compatibility metadata (`required` / `complementary` / `compatible` / `incompatible`) the primary query mode.
- Stay token-thrifty by default; require explicit opt-in for full detail.
- Stay compatible with `CODE_MODE=true` (project default).
- Fail closed on schema mismatch, partial writes, or invalid input — never partial data.

## 3. Non-goals

- No FastMCP fork or custom resource server.
- No mounting the catalog as an OpenAPI resource (data dictionary ≠ API contract).
- No renames of existing `_CATALOG` entries (`rp_createAsyncReport`, `br_generateBrandMetricsReport`, `mmm_createMmmReport` stay as-is).
- No live-API field validation (tracked as follow-up).
- No pre-flight validation for non-v1 report operations (they already have enumerated schemas).
- No proactive `documented → empirical` upgrades in this PR; that is the follow-up work per §8.4.

## 4. Design

### 4.1 Runtime catalog layout

```
src/amazon_ads_mcp/resources/adsv1/
├── dimensions.json       # 118 entries, full records
├── metrics.json          # 700 entries, full records
├── index.json            # routing map only (see shape below)
└── catalog_meta.json     # {schema_version, parsed_at, generated_at, generator_version, source_commit, source_files_sha256, output_files_sha256}
```

**`index.json` shape (routing map, no byte offsets):**
```json
{
  "schema_version": 1,
  "fields": {
    "metric.clicks":     {"file": "metrics",    "category": "metric"},
    "campaign.id":       {"file": "dimensions", "category": "dimension"}
  }
}
```

- **Lock-free lazy load.** `dimensions.json` and `metrics.json` are each loaded at most once per process via a module-level sentinel. Concurrent first-callers may both parse; both produce identical results and one is GC'd. This is acceptable for a read-only one-time init of ~1.4 MB. Documented in the loader module docstring; do not add a lock without measured contention.
- **Single-field detail:** `index.json → entry.file → dict[field_id]`. No byte offsets, no fixed-format requirement.
- **Compact form:** `index.json` and listing responses omit `description` and `source.*`. Detail responses (`fields=[...]` lookup) include them.
- **Explicit file list, no glob.** The loader opens only four fixed paths:
  ```python
  _CATALOG_FILES = {"metrics": "metrics.json", "dimensions": "dimensions.json"}
  _META_FILE = "catalog_meta.json"
  _INDEX_FILE = "index.json"
  ```
  A stray JSON dropped into `resources/adsv1/` is surfaced as an obvious lookup miss rather than silently included. `.tmp` filtering is unnecessary because only named paths are ever opened.
- **`index.json` entries pointing to anything other than `"metrics"` or `"dimensions"` raise `CatalogSchemaError`.**

**Commit-signal verification (load-time fail-closed):**

On **first access to any catalog file**, the loader:

1. Reads `catalog_meta.json`. If missing, raises `CatalogSchemaError(CATALOG_SCHEMA_MISMATCH)` with message `"catalog_meta.json not found — refresh never completed"`.
2. Checks `catalog_meta.schema_version` against `runtime.SUPPORTED_SCHEMA_VERSION`. **Any mismatch in either direction** (old runtime + new catalog, or new runtime + old catalog) raises `CATALOG_SCHEMA_MISMATCH`. No permissive fallback. See §4.7.
3. Computes SHA-256 of on-disk `dimensions.json` and `metrics.json`, compares against `catalog_meta.output_files_sha256`. Mismatch raises `CATALOG_SCHEMA_MISMATCH` with message `"interrupted refresh detected — on-disk hashes do not match catalog_meta.output_files_sha256"`.

This makes `catalog_meta.json` the **actual** commit signal the refresh protocol claims it to be. An interrupted refresh that wrote new `dimensions.json` but left old `metrics.json` and old `catalog_meta.json` is caught on the next load and fails closed rather than serving mixed data.

### 4.2 Provenance vocabulary (locked — 3 values, no fourth without spec change)

| Value | Meaning | Current source |
|---|---|---|
| `empirical` | Validated by live API success in a real session | `_ADSAPI_V1_SAFE_FIELDS` baseline |
| `documented` | Scraped from `advertising.amazon.com` guides | New v1 catalog (118 + 700) |
| `schema-derived` | Pulled from OpenAPI / request schemas | Existing v3 / Brand Metrics / MMM entries |

Every returned field carries `provenance`. CI test enforces no field escapes without it.

### 4.3 Tool surface — one new tool, discriminated by `mode`

```python
list_report_fields(operation: str | None = None) -> ListReportFieldsResponse
# Unchanged. Returns curated baseline. Schema-compatible with current response.

report_fields(
    mode: Literal["query", "validate"],                          # required discriminator
    operation: str = "allv1_AdsApiv1CreateReport",
    # --- query-mode args (rejected in validate mode) ---
    category: Literal["dimension", "metric", "filter", "time"] | None = None,
    search: str | None = None,                                   # substring on field_id + display_name
    compatible_with: list[str] | None = None,                    # AND semantics (intersection)
    requires: list[str] | None = None,                           # fields whose required_fields ⊆ given
    fields: list[str] | None = None,                             # exact-id detail lookup
    include_v3_mapping: bool = False,
    limit: int = 25,                                             # max 100
    offset: int = 0,
    # --- validate-mode args (rejected in query mode) ---
    validate_fields: list[str] | None = None,
) -> ReportFieldsResponse   # tagged union on `mode`
```

**Schema hardening (locked):**
- Request model: `model_config = ConfigDict(extra="forbid")`. Unknown args rejected.
- Response models carry `mode` as required discriminator; parsers use `Annotated[Union[...], Field(discriminator="mode")]`.
- Cross-mode arg contamination (e.g., `mode="query"` with `validate_fields` set) rejected before handler dispatch with error code `INVALID_MODE_ARGS`.
- `mode="query"` with no query-mode args also rejected (`INVALID_MODE_ARGS`) to prevent accidental full-catalog dump.

**Error codes (locked enumeration):**
| Code | Meaning |
|---|---|
| `INVALID_MODE_ARGS` | Missing required args for mode, or cross-mode contamination |
| `UNSUPPORTED_OPERATION` | Operation not in catalog and not alias-resolvable |
| `CATALOG_SCHEMA_MISMATCH` | Runtime cannot handle packaged `schema_version` |
| `INVALID_INPUT_SIZE` | Input list/string exceeds cap (see §4.10) |
| `UNKNOWN_FIELD` | Referenced field_id not in catalog (validate mode) |

**Naming convention (locked):** input `category` values, `ReportFieldEntry.category`, and all internal identifiers use **singular** forms (`"dimension"`, `"metric"`, `"filter"`, `"time"`).

### 4.4 Validate scope (v1-only)

- `operation == "allv1_AdsApiv1CreateReport"` (or alias): full graph validation — returns `unknown_fields`, `missing_required`, `incompatible_pairs`, `suggested_replacements`.
- Any other operation: `success=false` with `error_code=UNSUPPORTED_OPERATION` and message:
  > `"validate mode supports only allv1_AdsApiv1CreateReport (the sole operation with a compatibility graph). For other report APIs, use list_report_fields(operation=...) to inspect their enumerated schemas."`

Rationale: `rp_*`, `br_*`, `mmm_*` use `request_schema` (not `field_groups`), so flat membership would be ambiguous against the current `_CATALOG` shape. Those APIs already have enumerated schemas; the failure loop does not exist there.

### 4.5 Response shapes

```python
class CatalogSourceMeta(BaseModel):
    model_config = ConfigDict(extra="forbid")
    md_file: str
    parsed_at: str                                      # ISO timestamp

class QueryReportFieldsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["query"]                              # discriminator
    success: bool
    operation: str
    catalog_schema_version: int
    parsed_at: str                                      # ISO timestamp
    stale_warning: str | None = None                    # when parsed_at > LIST_REPORT_FIELDS_STALE_DAYS
    truncated: bool = False
    truncated_reason: Literal["byte_cap", "limit", "field_filter"] | None = None
    total_matching: int                                 # before pagination
    returned: int
    offset: int
    limit: int
    fields: list[ReportFieldEntry]                      # sorted ascending by field_id

class ReportFieldEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")
    field_id: str
    display_name: str
    data_type: str
    category: Literal["dimension", "metric", "filter", "time"]
    provenance: Literal["empirical", "documented", "schema-derived"]
    short_description: str                              # always; ≤ 160 chars
    description: str | None = None                      # detail lookup only
    # Always-applicable lists (may be empty; always included in output):
    required_fields: list[str] = []
    complementary_fields: list[str] = []
    # Category-conditional lists (None when not applicable; excluded from output via exclude_none):
    compatible_dimensions: list[str] | None = None      # only when category == "dimension"
    incompatible_dimensions: list[str] | None = None    # only when category == "dimension"
    # Optional cross-references (None when not requested or not applicable):
    v3_name_dsp: str | None = None                      # only when include_v3_mapping=True
    v3_name_sponsored_ads: str | None = None
    source: CatalogSourceMeta | None = None             # detail only

class ValidateReportFieldsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["validate"]                           # discriminator
    success: bool
    operation: str
    valid: bool
    unknown_fields: list[str]
    missing_required: dict[str, list[str]]              # {field: [required_dependencies]}
    incompatible_pairs: list[tuple[str, str]]
    suggested_replacements: dict[str, list[str]]        # {bad_field: [candidates]}

ReportFieldsResponse = Annotated[
    QueryReportFieldsResponse | ValidateReportFieldsResponse,
    Field(discriminator="mode"),
]
```

**Serialization policy (locked):** responses are serialized at the MCP boundary with `model_dump(exclude_none=True, by_alias=False)`. `None`-valued optional fields drop from the JSON output; empty lists on always-applicable fields (`required_fields`, `complementary_fields`) are preserved as `[]` for semantic clarity. This policy is enforced at the serializer boundary (§4.6), not left to model defaults.

### 4.6 Token / size budgets (hard contract)

| Response class | Hard cap | Default behavior |
|---|---|---|
| `list_report_fields()` no args | ≤ 2 KB | unchanged (~1 KB today) |
| `report_fields(mode="query")` listing (limit ≤ 25) | ≤ 6 KB | descriptions clipped to `short_description` |
| `report_fields(mode="query")` listing (limit = 100 max) | ≤ 16 KB | descriptions clipped |
| `report_fields(mode="query")` detail (`fields=[...]`) | ≤ 16 KB total | full description; truncate + `truncated=true` + `truncated_reason="byte_cap"` if hit |
| `report_fields(mode="validate")` | ≤ 4 KB | — |

**Enforcement is at the serializer boundary:** byte counting runs against the final MCP-serialized JSON payload (`model_dump(exclude_none=True)` → `json.dumps` → `len(encode("utf-8"))`) after response assembly and immediately before return. Tested against worst-case constructed inputs.

**Oversized responses clip descriptions; never silently drop fields.** `truncated_reason` carries one of `"byte_cap" | "limit" | "field_filter"`.

**Stable ordering:** `fields` array sorted ascending by `field_id`. Guaranteed by test. Enables agents to cache on `(operation, args) → fields` without silent diffs.

Configurable env vars:
- `LIST_REPORT_FIELDS_MAX_BYTES` (default `16384`)
- `LIST_REPORT_FIELDS_STALE_DAYS` (default `90`)

### 4.7 Catalog schema version policy

- Every response includes `catalog_schema_version: int`.
- `response_schema_version` and `catalog_schema_version` are **coupled** — versioned as one field. Split only if a concrete case requires independent evolution.
- **Strict versioning (locked):** any mismatch between `catalog_meta.schema_version` and `runtime.SUPPORTED_SCHEMA_VERSION` — in **either direction** — raises `CatalogSchemaError(CATALOG_SCHEMA_MISMATCH)`. No permissive `<=` fallback; no deprecation warnings that silently succeed.
  - Old runtime + new catalog: fails closed.
  - New runtime + old catalog: fails closed.
  - Matches the fail-closed goal in §2; eliminates a class of silent-drift bugs.
- `extra="forbid"` on `ReportFieldEntry` ensures an old runtime rejects a new-catalog field (e.g., `v4_name_*`) rather than silently dropping it.
- Migration changes must land in the same PR as the reader update.

### 4.8 Code Mode interaction

With `CODE_MODE=true` (project default), tools are surfaced via `Search` / `GetSchemas` / `GetTags` meta-tools; the LLM writes Python that calls `await call_tool(...)` in the Monty sandbox.

- Both tools (`list_report_fields`, `report_fields`) tagged `BUILTIN_TAG = "server-management"` (consistent with `code_mode.py:tag_builtin_tools`).
- Reachable via `Search` on keywords: `"report fields"`, `"v1 catalog"`, `"validate"`.
- Schemas returned by `GetSchemas` so the LLM can construct typed args for `call_tool` inside `execute`.
- Byte caps verified against the MCP-serialized response flowing through `call_tool`, not the Python object.

### 4.9 Refresh pipeline

```bash
python -m amazon_ads_mcp.build.refresh_v1_catalog \
    --source .build/adsv1_specs \
    --dest src/amazon_ads_mcp/resources/adsv1 \
    --validate           # schema-validate source records
    --check              # fail if dest would change (CI mode)
```

**Responsibilities:**
1. Sweep and remove any orphaned `*.tmp` files in `--dest` before starting.
2. Read raw `.build/adsv1_specs/*.json`.
3. Validate source records against `scripts/schemas/adsv1_catalog.schema.json`. Reject if any record is missing `field_id`, `display_name`, or `source.parsed_at`.
4. **Normalize field_ids deterministically:** `.strip()`, case policy preserved as-is (field IDs are case-sensitive per Amazon docs), dedupe with first-wins.
5. **Charset enforcement (strongly recommended, treated as required):** every `field_id` must match `^[a-zA-Z0-9._-]+$`. Fields containing whitespace, control characters, zero-width spaces, smart quotes, or any character outside this set → hard fail. Catches scraping artifacts that would otherwise become unfindable fields.
6. **Enforce uniqueness** of `field_id` across metrics + dimensions combined. Duplicate → hard fail.
7. **Integrity checks:**
   - Every id referenced in `required_fields` and `complementary_fields` must exist in the combined catalog.
   - Run `required_fields` cycle detection (DFS). Cycles → hard fail (data bug).
   - These checks run at refresh time in CI only, never at runtime.
8. **Atomic writes** — for each output file:
   - Write `<name>.json.tmp`.
   - `os.replace(<name>.json.tmp, <name>.json)` in this order: `dimensions.json`, `metrics.json`, `index.json`, `catalog_meta.json` **last**.
   - `catalog_meta.json` is the commit signal (verified at load time per §4.1, not just by presence).
   - Runtime loader opens only the four named files; `*.tmp` are never enumerated.
9. **Deterministic formatting:** sorted keys, stable indent, trailing newline. Running refresh twice produces zero diff.
10. **Provenance manifest** stamped into `catalog_meta.json`:
   ```json
   {
     "schema_version": 1,
     "parsed_at": "<max(source.parsed_at)>",
     "generated_at": "<utc-now>",
     "generator_version": "<package version>",
     "source_commit": "<git rev-parse HEAD>",
     "source_files_sha256": {
       "amazon_ads_v1_dimensions.json": "<sha256 of raw source>",
       "amazon_ads_v1_metrics.json": "<sha256 of raw source>"
     },
     "output_files_sha256": {
       "dimensions.json": "<sha256 of packaged output>",
       "metrics.json": "<sha256 of packaged output>"
     }
   }
   ```

   `source_files_sha256` tracks provenance from raw `.build/adsv1_specs/`. `output_files_sha256` is what the **loader verifies at §4.1 step 3** against on-disk `dimensions.json` / `metrics.json` to detect interrupted refreshes.

**CI gates (run on every PR, not conditional on path changes):**
- `refresh_v1_catalog --check` → fails on any diff between source and packaged catalog.
- Refresh idempotency test → runs refresh twice, asserts zero diff between runs.
- Negative-path test → runs refresh against a deliberately corrupted fixture, asserts non-zero exit with specific error code.
- Minimum-content floors → `dimensions.json ≥ 100`, `metrics.json ≥ 600` entries. Override path: set `ALLOW_CATALOG_COUNT_DROP=true` in CI with CODEOWNERS sign-off.
- Wheel smoke test → build wheel in a clean env, install into a scratch venv, import `amazon_ads_mcp.tools.report_fields_v1_catalog`, execute a representative query. Catches packaging-backend misconfiguration that source-tree tests miss.

### 4.10 Input sanitation caps

Enforced before handler dispatch. Exceeding any cap → `INVALID_INPUT_SIZE`.

| Input | Cap |
|---|---|
| `fields` list length | ≤ 200 |
| `validate_fields` list length | ≤ 200 |
| `compatible_with` list length | ≤ 50 |
| `requires` list length | ≤ 50 |
| `search` string length | ≤ 200 chars |

Prevents DoS-adjacent graph-intersection queries from a runaway caller.

### 4.11 Observability

No new dependencies (no Prometheus, no OpenTelemetry). All observability is structured Python logging with stable JSON in `extra`, emitted via the standard library `logging` module already used throughout the codebase. A downstream log aggregator can derive metrics without us taking on an instrumentation library.

- **Structured log line on first catalog load** (INFO):
  ```python
  logger.info("catalog_loaded", extra={
      "event": "catalog_loaded",
      "schema_version": 1,
      "parsed_at": "<iso>",
      "dimensions": <n>,
      "metrics": <n>,
      "source_commit": "<sha>",
  })
  ```
- **Structured call/error events** (INFO/WARN as appropriate):
  ```python
  logger.info("report_fields_call", extra={"event": "report_fields_call", "mode": "query", "operation": "..."})
  logger.info("report_fields_truncation", extra={"event": "report_fields_truncation", "reason": "byte_cap"})
  logger.warning("report_fields_error", extra={"event": "report_fields_error", "code": "INVALID_MODE_ARGS"})
  ```
  Event names (`catalog_loaded`, `report_fields_call`, `report_fields_truncation`, `report_fields_error`) are contract strings — changes to them are reviewable.
- **Debug helper:** env-gated builtin `_report_fields_debug` (hidden unless `AMAZON_ADS_DEBUG_TOOLS=true`) returns loaded `schema_version`, `parsed_at`, entry counts, and `source_commit`. No secondary execution surface.

### 4.12 Packaging

Repo uses `poetry-core` backend (`pyproject.toml:11-13`). The existing entry at `pyproject.toml:38-40` uses a non-recursive glob and `format = "wheel"` (string):

```toml
[[tool.poetry.include]]
path = "src/amazon_ads_mcp/resources/*.json"
format = "wheel"
```

This glob does **not** recurse into `resources/adsv1/`, so explicit per-file entries are required. **Match the existing `format = "wheel"` string convention** (do not introduce a second `["sdist", "wheel"]` convention side-by-side):

```toml
[[tool.poetry.include]]
path = "src/amazon_ads_mcp/resources/adsv1/dimensions.json"
format = "wheel"

[[tool.poetry.include]]
path = "src/amazon_ads_mcp/resources/adsv1/metrics.json"
format = "wheel"

[[tool.poetry.include]]
path = "src/amazon_ads_mcp/resources/adsv1/index.json"
format = "wheel"

[[tool.poetry.include]]
path = "src/amazon_ads_mcp/resources/adsv1/catalog_meta.json"
format = "wheel"
```

Wheel-content test asserts all four JSON files are present inside the built `.whl`. The CI wheel smoke test (§4.9) is the ultimate backstop — it catches any backend-config drift regardless of how the test suite is worded.

## 5. Acceptance criteria

### Behavior preservation
- [ ] `list_report_fields()` no-arg response parses to the same JSON structure and values as the current implementation (deep-equality snapshot test — not byte-for-byte).
- [ ] `list_report_fields(operation="allv1_AdsApiv1CreateReport")` returns the existing minimal baseline, NOT the 800+ entry catalog.
- [ ] Existing `_CATALOG` entries for `rp_*`, `br_*`, `mmm_*` unchanged.

### Tool surface
- [ ] `report_fields` accepts `mode ∈ {"query", "validate"}` as required discriminator.
- [ ] `extra="forbid"` on request and response models; unknown args rejected.
- [ ] Cross-mode arg contamination rejected with `INVALID_MODE_ARGS`.
- [ ] `mode="query"` with no query-mode args rejected with `INVALID_MODE_ARGS`.
- [ ] Error-code enumeration from §4.3 exhaustive — no free-text-only error paths in the tool handler.
- [ ] **Code-review checklist item (implementation):** every raised error uses one of the five locked codes from §4.3 (`INVALID_MODE_ARGS`, `UNSUPPORTED_OPERATION`, `CATALOG_SCHEMA_MISMATCH`, `INVALID_INPUT_SIZE`, `UNKNOWN_FIELD`). Codes defined as an `enum.StrEnum` in a single module; grep for raised strings during PR review to confirm no drift.

### Discovery & validation
- [ ] Query mode supports `category`, `search`, `compatible_with` (AND semantics), `requires`, `fields`, `include_v3_mapping`, `limit` (max 100), `offset`.
- [ ] Query results sorted ascending by `field_id` — asserted by test.
- [ ] Validate mode returns all four diagnostic fields for `allv1_AdsApiv1CreateReport`.
- [ ] Validate mode on any other operation returns `success=false` with `error_code=UNSUPPORTED_OPERATION`.

### Provenance & freshness
- [ ] Every returned field carries `provenance ∈ {empirical, documented, schema-derived}` — CI-enforced.
- [ ] Every response includes `catalog_schema_version` and `parsed_at`.
- [ ] `stale_warning` populated when catalog `parsed_at > LIST_REPORT_FIELDS_STALE_DAYS` (default 90, configurable).
- [ ] `CATALOG_SCHEMA_MISMATCH` raised when runtime reader can't handle packaged `schema_version`.
- [ ] Docs explicitly state v1 `query.fields` is not enumerated in Amazon OpenAPI; v1 catalog provenance is `documented` (scraped), not API-validated.

### Performance
- [ ] Catalog files are not opened at module import — verified by test that monitors `open()` calls under `amazon_ads_mcp.tools.report_fields_v1_catalog` import.
- [ ] Lock-free first-load explicitly documented in the loader module docstring.
- [ ] Server startup benchmark reported via `pytest-benchmark` as non-gating informational output, with a **soft regression threshold**: warn when median startup exceeds baseline + 50 ms so benchmark noise is filtered.

### Token budget
- [ ] All response classes respect byte caps in §4.6 — asserted on serialized JSON payloads (not Python objects).
- [ ] Byte enforcement runs after response assembly and before return.
- [ ] Oversized responses set `truncated: true` + `truncated_reason`; never silently drop fields.

### Input sanitation
- [ ] Input caps from §4.10 enforced before handler dispatch. Exceeding any cap → `INVALID_INPUT_SIZE`.

### Code Mode
- [ ] Both tools tagged `server-management` and reachable via `Search`/`GetSchemas`.
- [ ] Integration test exercises `await call_tool("report_fields", {"mode": "query", ...})` inside a Monty sandbox `execute` block.
- [ ] Byte caps verified on the MCP-serialized response flowing through `call_tool`.

### Refresh pipeline
- [ ] `refresh_v1_catalog` produces deterministic output (repeated runs → zero diff — **refresh idempotency test**).
- [ ] Atomic writes: `*.tmp` → `os.replace`, commit order `dimensions → metrics → index → catalog_meta`. `catalog_meta.json` is the commit signal, verified at load time (§4.1).
- [ ] Loader opens only the four named files; `*.tmp` are never enumerated.
- [ ] Orphaned `*.tmp` swept from `--dest` at refresh start.
- [ ] Schema validator catches malformed source records before they reach packaged metadata.
- [ ] `field_id` matches `^[a-zA-Z0-9._-]+$`; refresh fails hard on any violation (catches scraping artifacts).
- [ ] Uniqueness of `field_id` across metrics + dimensions enforced.
- [ ] Integrity check: every id in `required_fields` / `complementary_fields` exists in catalog.
- [ ] Cycle detection on `required_fields` graph → hard fail at refresh time.
- [ ] Negative-path CI: refresh against corrupted fixture → non-zero exit with specific error code.
- [ ] Minimum-content floors enforced (`≥ 100` dimensions, `≥ 600` metrics) with `ALLOW_CATALOG_COUNT_DROP` override.
- [ ] `catalog_meta.json` carries `generated_at`, `generator_version`, `source_commit`, `source_files_sha256`, and `output_files_sha256`.

### Commit-signal verification (loader)
- [ ] Loader raises `CATALOG_SCHEMA_MISMATCH` when `catalog_meta.json` is missing.
- [ ] Loader raises `CATALOG_SCHEMA_MISMATCH` on **any** `schema_version` mismatch (strict, both directions).
- [ ] Loader verifies `output_files_sha256` from `catalog_meta.json` against on-disk hashes of `dimensions.json` and `metrics.json` on first load; mismatch raises `CATALOG_SCHEMA_MISMATCH`.
- [ ] Interrupted-refresh test: write new `dimensions.json` + leave old `metrics.json` + leave old `catalog_meta.json` → loader fails closed; no mixed data returned.

### Packaging
- [ ] Built wheel contains `amazon_ads_mcp/resources/adsv1/*.json` — asserted by post-build test.
- [ ] Wheel smoke test installs the built wheel into a scratch venv and executes a representative query.

### Tool description stability
- [ ] Description for `report_fields` tool contains the semantic clauses: `"mode"`, `"query"`, `"validate"`, `"v1 catalog"`, and references `list_report_fields` as the baseline. Test asserts clause presence, not exact wording.

### Cross-references
- [ ] PR description cites this work as closing Issue 4.

## 6. File-level changes

```
NEW   src/amazon_ads_mcp/resources/adsv1/dimensions.json
NEW   src/amazon_ads_mcp/resources/adsv1/metrics.json
NEW   src/amazon_ads_mcp/resources/adsv1/index.json
NEW   src/amazon_ads_mcp/resources/adsv1/catalog_meta.json
NEW   src/amazon_ads_mcp/tools/report_fields_v1_catalog.py   # lazy loader + query + validate handlers
NEW   src/amazon_ads_mcp/build/refresh_v1_catalog.py         # refresh CLI with --check / --validate
NEW   scripts/schemas/adsv1_catalog.schema.json              # source-record JSON Schema
NEW   tests/fixtures/adsv1_catalog_pathological/             # duplicate ids, broken refs, cycles, stale ts
NEW   tests/unit/test_report_fields_v1_catalog.py
NEW   tests/unit/test_report_fields_lazy_load.py             # asserts no catalog I/O at import
NEW   tests/unit/test_wheel_package_data.py                  # asserts JSON shipped in wheel
NEW   tests/unit/test_refresh_v1_catalog.py                  # idempotency, atomic writes, integrity
NEW   tests/unit/test_report_fields_tool_description.py      # semantic-clause checklist
NEW   tests/integration/test_report_fields_code_mode.py
NEW   tests/integration/test_wheel_smoke.py                  # installs wheel into scratch venv; @pytest.mark.slow — CI only, not local dev
NEW   tests/unit/test_loader_commit_signal.py                # interrupted-refresh + schema-version mismatch scenarios
EDIT  src/amazon_ads_mcp/tools/report_fields.py              # _CATALOG intact
EDIT  src/amazon_ads_mcp/models/builtin_responses.py         # + QueryReportFieldsResponse, ValidateReportFieldsResponse, ReportFieldEntry, ReportFieldsResponse union
EDIT  src/amazon_ads_mcp/server/builtin_tools.py             # register report_fields (+ optional _report_fields_debug)
EDIT  src/amazon_ads_mcp/server/async_hints_transform.py     # update AdsApiv1CreateReport hint to point at report_fields
EDIT  pyproject.toml                                         # [[tool.poetry.include]] entries
EDIT  .github/workflows/*                                    # drift check, idempotency, negative-path, wheel smoke
EDIT  CLAUDE.md / AGENTS.md                                  # document new tool + refresh CLI + env vars
```

## 7. Open questions (non-blocking)

1. **Confidence sub-scores** for `documented` (e.g., "doc-only" vs "doc + observed"): defer to follow-up unless obvious.
2. **Catalog refresh cadence:** who owns periodic re-scrape of `advertising.amazon.com`? Needs an assigned owner and incident-response path if a refresh parse fails.

## 8. Rollout

1. Land `report_fields` behind no feature flag — additive.
2. Update `AdsApiv1CreateReport` async hint to point LLMs at `report_fields` first. The hint must include a **complete example call**, not just a tool name, e.g.:
   ```
   Before CreateReport, call:
     report_fields(mode="validate", operation="allv1_AdsApiv1CreateReport",
                   validate_fields=["metric.clicks", "campaign.id"])
   To discover fields:
     report_fields(mode="query", category="metric", search="click")
   ```
3. Monitor adoption via structured log events (§4.11).
4. Follow-up PR: live-API validation pass to upgrade `documented → empirical` for highest-traffic fields.

## 9. Environment variables (new)

| Variable | Default | Purpose |
|---|---|---|
| `LIST_REPORT_FIELDS_MAX_BYTES` | `16384` | Hard byte cap on query/detail responses |
| `LIST_REPORT_FIELDS_STALE_DAYS` | `90` | Threshold for `stale_warning` on catalog freshness |
| `AMAZON_ADS_DEBUG_TOOLS` | `false` | When `true`, exposes `_report_fields_debug` builtin |
| `ALLOW_CATALOG_COUNT_DROP` | `false` | CI override for minimum-content floors (requires CODEOWNERS sign-off) |

---

## TL;DR

Two tools (`list_report_fields` unchanged + new `report_fields` with `mode ∈ {"query", "validate"}`), four packaged JSON files under `resources/adsv1/` opened by **explicit name** (no glob), lock-free lazy load via routing-map `index.json`, strict `extra="forbid"` + discriminated-union responses + typed `CatalogSourceMeta` + enumerated error codes, v1-only validation scope, hard byte caps enforced at the serializer boundary with `exclude_none=True` serialization and `truncated_reason`, stable ascending sort on `field_id`, input sanitation caps, locked three-value provenance vocabulary, **strict bidirectional** catalog/response schema version coupling with fail-closed mismatch, atomic refresh writes (`*.tmp` → `os.replace`, commit order `dimensions → metrics → index → catalog_meta` last), **loader verifies `output_files_sha256` from `catalog_meta.json` against on-disk hashes on first load** so interrupted refreshes fail closed rather than serve mixed data, charset regex on `field_id`, integrity + cycle checks at refresh time, CI gates on every PR (drift, idempotency, negative-path, content floors with `ALLOW_CATALOG_COUNT_DROP` override, wheel smoke test marked slow), provenance manifest in `catalog_meta.json`, Poetry `[[tool.poetry.include]]` packaging matching the existing `format = "wheel"` convention, structured log events (no new metrics dependency), and full Code Mode compatibility. Compatibility graph drives the query API. No silent shape mutation of the existing response. Closes Issue 4.
