# Runtime Behavior Contract

This document covers Amazon Ads MCP-specific behaviors that layer on top of
the cross-server v1 envelope contract at
[`openbridge-mcp/CONTRACT.md`](https://github.com/openbridge/openbridge-mcp/blob/main/CONTRACT.md).

## Error envelope contract (v1)

Every error response from this server is shaped as:

```json
{
  "error_kind": "ads_api_http",
  "tool": "adsv1_list_campaigns",
  "summary": "Amazon Ads API request failed with HTTP 400.",
  "details": [{"path": "campaignId", "issue": "Invalid format", "received_type": "str"}],
  "hints": ["Inspect details for upstream error codes and messages."],
  "examples": [],
  "error_code": "ADS_API_HTTP_400",
  "retryable": false,
  "_envelope_version": 1
}
```

### Supported `error_kind` values

| Value | Meaning |
|---|---|
| `mcp_input_validation` | Pydantic / FastMCP / Ads-side `ValidationError` rejected before any upstream call |
| `ads_api_http` | Amazon Ads API returned an HTTP 4xx/5xx response (excluding 429) |
| `auth_error` | Authentication or permission problem (covers `AuthenticationError`, `OAuthError`, `OAuthStateError`, `TokenError`, `MCPError(category=AUTHENTICATION/PERMISSION)`) |
| `rate_limited` | Upstream returned 429 OR `RateLimitError` raised pre-flight |
| `internal_error` | Unhandled exception or server-side error before reaching the upstream API |

`ads_api_client` is reserved for future use (currently routed through
`internal_error`).

### `legacy_error_kind` migration window

For one release after the contract bump, error envelopes include a
`legacy_error_kind` field carrying the prior taxonomy value (the old
`ErrorCategory` enum string or the `code` attribute on
`AmazonAdsMCPError` subclasses). Consumers branching on the old shape have
that release to migrate to `error_kind`. After the cutover release,
`legacy_error_kind` is dropped.

See `CHANGELOG.md` for the cutover date.

## `_meta.normalized` pre-flight normalization telemetry

The schema-driven key normalization middleware (`middleware/schema_normalization.py`)
rewrites caller-supplied tool argument keys to canonical schema field names
before FastMCP validation runs. When telemetry is enabled, the events are
surfaced under `_meta.normalized` on both successful responses and error
envelopes.

### Configuration

| Env var | Default | Effect |
|---|---|---|
| `MCP_SCHEMA_KEY_NORMALIZATION_ENABLED` | `true` | Master switch. Set `false` as an escape hatch when Amazon ships fields ahead of the OpenAPI spec. |
| `MCP_SCHEMA_KEY_NORMALIZATION_META` | `false` | Emit `_meta.normalized` events on responses. Default off pending soak (see Phase 5 below). |

### Phase 5 default-on gate

The plan flips `MCP_SCHEMA_KEY_NORMALIZATION_META` to default `true` in
lockstep with the SP server when these gates are met:

- ≥2 weeks of operator-enabled telemetry with no unresolved payload-size
  or parsing complaints
- ≥3 production deployments running with telemetry on
- Zero agent-side parsing complaints in support tickets
- Cross-server conformance suite continues to pass

The flip is a one-line change in
`src/amazon_ads_mcp/config/settings.py` (`mcp_schema_key_normalization_meta`
default). The env var stays in place as an opt-out for noise-sensitive
deployments. Both servers must flip on the same calendar day.

### Behavior contract

- **Unique schema match** → rewrite to canonical key
- **Ambiguous match** → unchanged (passes through; emits `unknown_field_passed_through`)
- **No match** → unchanged (passes through; emits `unknown_field_passed_through`)
- **Canonical present alongside alias** → drop alias (emits `dropped_alias`)
- **Schema is array-typed but client provided scalar** → wrap to single-item list (emits `coerced`)

### Event kinds (v1)

- `renamed`
- `dropped_alias`
- `coerced`
- `unknown_field_passed_through`

Reserved (not emitted in v1; reserved for future policy changes):
`unknown_field_dropped`.

### Coexistence with declarative aliasing

This server *also* runs a separate declarative aliasing system in
`server/sidecar_middleware.py` for operation-specific overlays (e.g.,
rewriting v1 reports `reportId` → `reportIds=[...]`). The two systems run
independently:

- `SidecarTransformMiddleware` (overlay-driven, Ads-specific operation
  fixes)
- `SchemaKeyNormalizationMiddleware` (cross-server v1 contract,
  schema-driven generic normalization)

Both run before tool dispatch. The schema-driven layer does not duplicate
or conflict with the overlay layer.

## Middleware ordering

The tool-call middleware chain is wired in `server/server_builder.py`:

1. **`ErrorEnvelopeMiddleware`** (outermost, registered first) — catches
   every exception raised below it and translates to a v1 envelope
   `ToolError`.
2. **`SchemaKeyNormalizationMiddleware`** — schema-driven canonical key
   rewrite before downstream guardrails see input.
3. **`ErrorHandlingMiddleware`** (FastMCP built-in) — covers non-tool
   error paths (resources, prompts) the envelope middleware doesn't touch.
4. **Auth / OAuth / sampling middleware** (provider-specific).
5. **`SidecarTransformMiddleware`** (operation-specific aliasing
   overlays) when registered.
6. **Tool dispatch** (innermost).

This ordering is locked by a unit test
(`tests/unit/test_envelope_middleware_ordering.py`).

## Code Mode error translation

When a tool call inside `execute` fails, the envelope middleware
transforms the exception into a `ToolError` carrying envelope JSON. The
Code Mode auth bridge then translates that `ToolError` into a
`RuntimeError` so the sandbox's `try/except RuntimeError:` can catch it.

Translation rule (verified by `tests/unit/test_code_mode_error_translation.py`):

- v1 envelope `ToolError` → `RuntimeError(f"{error_kind}: {summary}")`
- non-envelope `ToolError` → `RuntimeError(f"ToolError: {body}")`
- `RuntimeError` already → pass through unchanged
- any other `Exception` → `RuntimeError(f"{TypeName}: {message}")`

The full envelope (with `hints`, `error_code`, `retryable`,
`_meta.normalized`, etc.) is available to agents that catch on the
*outside* of `execute`. In-sandbox introspection is intentionally limited
to `error_kind` and `summary` to keep `try/except RuntimeError:` simple
for LLM-generated code.

### `EXECUTE_DESCRIPTION` is the source of truth

The `EXECUTE_DESCRIPTION` constant in `server/code_mode.py` is the prompt
the LLM sees. It documents the in-sandbox error format. If the
translation behavior changes, the description must move in lockstep —
this is locked by
`tests/unit/test_code_mode_error_translation.py::test_execute_description_documents_envelope_translation`.

## See also

- [`README.md`](README.md) — user-facing documentation
- [`AGENTS.md`](AGENTS.md) — environment variables, Docker, contributor workflow
- [`openbridge-mcp/CONTRACT.md`](https://github.com/openbridge/openbridge-mcp/blob/main/CONTRACT.md) — canonical cross-server contract
