# Changelog

All notable changes to Amazon Ads MCP will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added (cross-server v1 envelope contract — Phase 4, warnings)
- **`_meta.warnings[]` on success responses.** Upstream RFC 7234 ``Warning``
  response headers are now parsed and surfaced under `_meta.warnings[]`
  with shape `{kind: "upstream_warning", summary, details, hints}`.
  Mirrors what SP has already shipped for warnings via
  `extract_response_meta`. Implemented by extending
  `utils/http/rate_limit_headers.py:extract_rate_limit_meta` with
  `_parse_warning_headers` and updating
  `middleware/meta_injection_middleware.py` to merge warnings into
  `_meta`.
- Per-server appendix vocabularies in `openbridge-mcp/CONTRACT.md`
  document additional reserved warning kinds Ads may emit for
  domain-specific conditions: `cached_or_stale_data`,
  `partial_results`, `profile_scope_warning`,
  `deprecated_parameter_accepted`. Detection of those conditions is
  a separate work item; the contract shape is in place.

### Added (cross-server v1 envelope contract — Phase 3, rate-limit telemetry)
- **`X-RateLimit-*` / `Retry-After` parsing on successful responses.** The
  resilient HTTP client (`utils/http/resilient_client.py`) now captures
  rate-limit metadata from every response into a per-call context-var,
  and the new `MetaInjectionMiddleware`
  (`middleware/meta_injection_middleware.py`) merges it into successful
  dict responses under `_meta.rate_limit` / `_meta.retry_after_seconds`.
  Same wire shape as Amazon SP MCP; only the per-server header names
  differ (`X-RateLimit-*` here vs `x-amzn-ratelimit-*` on SP).
- **Rate-limit telemetry on error envelopes.** The envelope translator
  now auto-extracts `X-RateLimit-*` and `Retry-After` headers from
  `httpx.HTTPStatusError` responses and merges them into the error
  envelope's `_meta` block. Caller-supplied `http_meta` overrides
  auto-extracted values for explicit control.
- New parser at `utils/http/rate_limit_headers.py:extract_rate_limit_meta`.
  Emits only parseable values; absent / unparseable headers result in
  absent keys, not synthetic `None`. Past `Retry-After` HTTP-dates clamp
  to `0.0`. Non-numeric `X-RateLimit-Limit` / `X-RateLimit-Remaining`
  pass through as raw strings.
- Per-call context-var helpers (`set_last_http_meta`,
  `get_last_http_meta`, `clear_last_http_meta`) added to
  `utils/http/rate_limit_headers.py` for capture and read across the
  middleware chain.

### Added (cross-server v1 envelope contract — Phase 2)
- **v1 cross-server error envelope contract.** All tool-call errors are
  now returned in a structured envelope conforming to
  [`openbridge-mcp/CONTRACT.md`](https://github.com/openbridge/openbridge-mcp/blob/main/CONTRACT.md):
  `{error_kind, tool, summary, details, hints, examples, error_code, retryable, _envelope_version}`.
  Cross-server agent code can now write a single error handler against
  this server and the [Amazon SP MCP server](https://github.com/openbridge/amazon-sp-mcp).
  See [`BEHAVIOR.md`](BEHAVIOR.md).
- New `error_envelope`, `error_envelope_middleware`, and
  `schema_normalization` modules under `src/amazon_ads_mcp/middleware/`.
  The envelope middleware is the outermost wrapper of the tool-call chain.
- `auth_error` taxonomy split: `AuthenticationError`, `OAuthError`,
  `OAuthStateError`, `TokenError`, plus
  `MCPError(category=AUTHENTICATION/PERMISSION)`, are now reported as
  `error_kind: "auth_error"`.
- `rate_limited` taxonomy: HTTP 429 responses and `RateLimitError` are
  now reported as `error_kind: "rate_limited"` with `retryable: true`.
- Schema-driven pre-flight key normalization
  (`SchemaKeyNormalizationMiddleware`). Caller-supplied keys (e.g.
  `MarketplaceIds`) are rewritten to the canonical schema name
  (`marketplaceIds`) before validation. Master switch:
  `MCP_SCHEMA_KEY_NORMALIZATION_ENABLED` (default `true`). Telemetry
  toggle: `MCP_SCHEMA_KEY_NORMALIZATION_META` (default `false` pending
  soak).
- New built-in `get_envelope_contract` tool exposing
  `{contract_version, error_kinds, normalized_kinds, env_vars, spec_url}`
  for agent introspection at startup.
- Code Mode error translation surfaces envelope-shaped `ToolError`
  exceptions inside the sandbox as
  `RuntimeError("<error_kind>: <summary>")`. The legacy
  `RuntimeError("<OriginalType>: <message>")` form remains for
  non-envelope exceptions. `EXECUTE_DESCRIPTION` updated in lockstep.

### Changed (cross-server v1 envelope contract — Phase 2)
- **BREAKING at the MCP boundary**: tool-call error responses now carry
  the v1 envelope shape instead of the prior `MCPError`/
  `AmazonAdsMCPError` `to_dict()` output. Internal callers of those
  exception classes are unaffected. Consumers branching on the old
  `category` enum string or matching `Internal error: <free text>`
  should migrate to `error_kind`. Migration window:
  `legacy_error_kind` is emitted alongside `error_kind` for one release
  after the version bump; consumers must migrate during that window.
  After the cutover release, `legacy_error_kind` is dropped.

### Added
- Initial release of Amazon Ads MCP
- MCP server implementation for Amazon Advertising API
- Authentication providers (Direct and Openbridge)
- OpenAPI-based dynamic tool generation
- Profile and region management
- Campaign management tools
- Reporting capabilities
- Docker support
- Comprehensive test suite

### Security
- Secure token storage implementation
- OAuth state management
- Environment-based credential handling

## Version History

This changelog will be automatically updated by our CI/CD pipeline when new releases are created.

---

*Note: Releases are automatically generated based on conventional commit messages:*
- `feat:` triggers minor version bump
- `fix:` triggers patch version bump
- `BREAKING CHANGE:` or `feat!:` triggers major version bump